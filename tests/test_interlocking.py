import json
import os
import tempfile

import pytest

from app import interlocking as il
from app.db import connect, init_db


@pytest.fixture()
def conn():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    c = connect(path)
    yield c
    c.close()
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


@pytest.fixture()
def yard(conn):
    with open(os.path.join(os.path.dirname(__file__), "..", "examples", "yard.json"), encoding="utf-8") as f:
        il.import_yard(conn, json.load(f))
    return json.load(open(os.path.join(os.path.dirname(__file__), "..", "examples", "yard.json"), encoding="utf-8"))


def ev(seq, detector, kind):
    return {"seq": seq, "detector_id": detector, "kind": kind, "ts": 123}


# ---------------- 导入校验 ----------------
def test_import_rejects_disconnected(conn):
    bad = {
        "yard_id": "x",
        "nodes": [{"id": "A"}, {"id": "B"}, {"id": "C"}, {"id": "D"}],
        "sections": [
            {"id": "S1", "a": "A", "b": "B", "detector": "D1"},
            {"id": "S2", "a": "C", "b": "D", "detector": "D2"},
        ],
        "switches": [],
        "resources": [],
        "routes": [{"id": "R1", "sections": ["S1", "S2"], "switches": {}, "flank": []}],
    }
    with pytest.raises(il.ClientError) as ei:
        il.import_yard(conn, bad)
    assert ei.value.status_code == 422
    assert any("不连通" in e for e in ei.value.extra["errors"])


def test_import_rejects_missing_section_reference(conn):
    bad = {
        "yard_id": "x",
        "nodes": [{"id": "A"}, {"id": "B"}],
        "sections": [{"id": "S1", "a": "A", "b": "B", "detector": "D1"}],
        "switches": [], "resources": [],
        "routes": [{"id": "R1", "sections": ["S1", "GHOST"], "switches": {}, "flank": []}],
    }
    with pytest.raises(il.ClientError) as ei:
        il.import_yard(conn, bad)
    assert any("不存在" in e for e in ei.value.extra["errors"])


def test_import_rejects_bad_switch_position(conn, yard):
    y = json.loads(json.dumps(yard))
    y["routes"][0]["switches"]["SW1"] = "reverse"
    with pytest.raises(il.ClientError) as ei:
        il.import_yard(conn, y)
    assert any("位置" in e for e in ei.value.extra["errors"])


def test_import_rejects_switch_on_path_but_undeclared(conn, yard):
    y = json.loads(json.dumps(yard))
    del y["routes"][0]["switches"]["SW1"]
    with pytest.raises(il.ClientError) as ei:
        il.import_yard(conn, y)
    assert any("未声明位置" in e for e in ei.value.extra["errors"])


# ---------------- 放行与互斥 ----------------
def test_route_permit_and_conflict(conn, yard):
    r = il.request_route(conn, "R-MAIN")
    assert r["decision"] == "permitted" and r["signal"] == "green"
    # 共用 S0/S3、侧防 FP-EAST
    r2 = il.request_route(conn, "R-SIDING")
    assert r2["decision"] == "denied" and r2["signal"] == "red"
    kinds = {c["type"] for c in r2["conflicts"]}
    assert "section_locked" in kinds and "flank_locked" in kinds
    # 快照能反映锁闭
    snap = il.snapshot(conn)
    assert any(l["resource_id"] == "S1" and l["route_id"] == "R-MAIN" for l in snap["locks"])


def test_gap_blocks_approval(conn, yard):
    il.report_event(conn, ev(2, "D0", "occupy"))  # 缺 #1
    with pytest.raises(il.ClientError) as ei:
        il.request_route(conn, "R-MAIN")
    assert ei.value.code == "sequence_gap"


# ---------------- 顺序占用/出清与逐段释放 ----------------
def _full_run_s0_to_s3(conn):
    """完整跑一趟 R-MAIN，返回各序结果。"""
    out = []
    seq = 1
    dets = ["D0", "D1", "D2", "D3"]
    for i, d in enumerate(dets):
        out.append(il.report_event(conn, ev(seq, d, "occupy"))); seq += 1
        if i > 0:
            prev = dets[i - 1]
            out.append(il.report_event(conn, ev(seq, prev, "clear"))); seq += 1
    out.append(il.report_event(conn, ev(seq, "D3", "clear")))
    return out


def test_section_release_requires_successor(conn, yard):
    il.request_route(conn, "R-MAIN")
    il.report_event(conn, ev(1, "D0", "occupy"))
    # S0 已占用但后继 S1 未占用 => S0 不释放
    r = il.report_event(conn, ev(2, "D0", "clear"))
    assert r["processed"][0]["state"]["event"] == "clear_waiting"
    snap = il.snapshot(conn)
    assert any(l["resource_id"] == "S0" for l in snap["locks"])
    # 后继 S1 占用，S0 仍未实际再次出清；补一条 S0 出清无效（已 clear）
    il.report_event(conn, ev(3, "D1", "occupy"))  # 推进时 S0 已 clear -> 释放
    snap = il.snapshot(conn)
    assert not any(l["resource_id"] == "S0" for l in snap["locks"])


def test_full_route_completion_releases_switches_and_flank(conn, yard):
    il.request_route(conn, "R-MAIN")
    _full_run_s0_to_s3(conn)
    snap = il.snapshot(conn)
    assert snap["instances"][-1]["status"] == "completed"
    # 道岔与侧防锁到末段出清后全部解除
    assert [l for l in snap["locks"] if l["route_id"] == "R-MAIN"] == []


def test_reapproval_after_completion(conn, yard):
    il.request_route(conn, "R-MAIN")
    _full_run_s0_to_s3(conn)
    r = il.request_route(conn, "R-SIDING")
    assert r["decision"] == "permitted"


# ---------------- 乱序缓冲与幂等 ----------------
def test_out_of_order_buffering_and_drain(conn, yard):
    il.request_route(conn, "R-MAIN")
    r3 = il.report_event(conn, ev(3, "D1", "occupy"))
    assert r3["buffered"] and r3["expected"] == 1
    r2 = il.report_event(conn, ev(2, "D0", "clear"))
    assert r2["buffered"] and r2["expected"] == 1
    # #1 到达，连续排空
    r1 = il.report_event(conn, ev(1, "D0", "occupy"))
    assert r1["status"] == "processed" and r1["drained"] == 3
    assert [x["seq"] for x in r1["processed"]] == [1, 2, 3]
    # 同序同内容幂等
    dup = il.report_event(conn, ev(1, "D0", "occupy"))
    assert dup["duplicate"] is True and dup["status"] == "processed"
    # 同序异内容拒绝
    with pytest.raises(il.ClientError) as ei:
        il.report_event(conn, {"seq": 1, "detector_id": "D0", "kind": "clear"})
    assert ei.value.code == "content_conflict"


# ---------------- 故障锁闭与复位 ----------------
def test_out_of_order_occupy_faults(conn, yard):
    il.request_route(conn, "R-MAIN")
    il.report_event(conn, ev(1, "D0", "occupy"))
    # 直接占用 S2（跳过 S1）=> 越序占用，故障锁闭
    r = il.report_event(conn, ev(2, "D2", "occupy"))
    assert r["processed"][0]["fault"] is True
    snap = il.snapshot(conn)
    assert snap["instances"][-1]["status"] == "faulted"
    # 缺号不存在但有故障：任何共用资源的放行被拒（锁仍在）
    r2 = il.request_route(conn, "R-SIDING")
    assert r2["decision"] == "denied"


def test_out_of_order_clear_faults_and_reset(conn, yard):
    il.request_route(conn, "R-MAIN")
    # 未占用即报出清 => 越序出清
    r = il.report_event(conn, ev(1, "D1", "clear"))
    assert r["processed"][0]["fault"] is True
    inst_id = r["processed"][0]["instance_id"]
    # 全段空闲（S1 出清态，其余空闲），可以复位
    res = il.reset_instance(conn, inst_id)
    assert res["reset"] is True
    snap = il.snapshot(conn)
    assert snap["instances"][-1]["status"] == "completed"


def test_reset_requires_all_clear(conn, yard):
    il.request_route(conn, "R-MAIN")
    il.report_event(conn, ev(1, "D0", "occupy"))
    il.report_event(conn, ev(2, "D2", "occupy"))  # 故障
    inst = il.snapshot(conn)["instances"][-1]
    assert inst["status"] == "faulted"
    with pytest.raises(il.ClientError) as ei:
        il.reset_instance(conn, inst["id"])  # D0、D2 仍占用
    assert ei.value.code == "reset_blocked"
    il.report_event(conn, ev(3, "D0", "clear"))
    il.report_event(conn, ev(4, "D2", "clear"))
    # 故障实例不再推进；清空后复位成功
    res = il.reset_instance(conn, inst["id"])
    assert res["reset"] is True


def test_gap_blocks_reset(conn, yard):
    il.request_route(conn, "R-MAIN")
    il.report_event(conn, ev(1, "D1", "clear"))  # 故障
    inst = il.snapshot(conn)["instances"][-1]["id"]
    il.report_event(conn, ev(3, "D2", "occupy"))  # 制造缺号 #2
    with pytest.raises(il.ClientError) as ei:
        il.reset_instance(conn, inst)
    assert ei.value.code == "sequence_gap"


def test_premature_last_section_clear_faults(conn, yard):
    """列车未按序到达末段：末段被占用即越序占用故障；之后出清不得误判完成。"""
    il.request_route(conn, "R-MAIN")
    il.report_event(conn, ev(1, "D0", "occupy"))
    # 末段 S3 在列车远未到达时被占用，且该段锁属于活动进路 => 越序占用故障
    r2 = il.report_event(conn, ev(2, "D3", "occupy"))
    assert r2["processed"][0]["fault"] is True
    snap = il.snapshot(conn)
    assert snap["instances"][-1]["status"] == "faulted"
    # 之后末段出清：故障进路不会被推进，也不得变成 completed
    il.report_event(conn, ev(3, "D3", "clear"))
    snap = il.snapshot(conn)
    assert snap["instances"][-1]["status"] == "faulted"
    assert all(l["instance_id"] == snap["instances"][-1]["id"] for l in snap["locks"])


# ---------------- 末段出清时的前段误解锁修复 ----------------
def test_last_clear_with_lingering_front_faults_and_keeps_locks(conn, yard):
    """末段已按序占用且出清，但前段 S1 已被后继占用推进、却始终未出清
    （锁仍归本实例且当前占用）：不得判完成，应故障锁闭并保留全部锁。"""
    il.request_route(conn, "R-MAIN")
    # 全程只占用、从不出清任何中间段，直至末段 S3 占用
    for s, d in enumerate(["D0", "D1", "D2", "D3"]):
        il.report_event(conn, ev(s + 1, d, "occupy"))
    snap = il.snapshot(conn)
    inst = snap["instances"][-1]
    assert inst["status"] == "active" and inst["position"] == 3
    # 此时 S0~S3 全部占用，各段锁、道岔、侧防均在
    held_sections = {l["resource_id"] for l in snap["locks"] if l["resource_type"] == "section"}
    assert held_sections == {"S0", "S1", "S2", "S3"}

    # 末段出清：S0/S1/S2 仍由本实例锁闭且占用 => 故障锁闭，锁一个都不能删
    r = il.report_event(conn, ev(5, "D3", "clear"))
    p = r["processed"][0]
    assert p["fault"] is True
    assert p["state"]["event"] == "fault"
    assert set(p["state"]["lingering"]) == {"S0", "S1", "S2"}
    snap = il.snapshot(conn)
    inst = snap["instances"][-1]
    assert inst["status"] == "faulted"
    assert {l["resource_type"] for l in snap["locks"]} == {"section", "switch", "flank"}
    held_sections = {l["resource_id"] for l in snap["locks"] if l["resource_type"] == "section"}
    assert held_sections == {"S0", "S1", "S2", "S3"}  # 末段锁也保留，含道岔/侧防


def test_lingering_fault_blocks_conflicting_route_until_reset(conn, yard):
    """前段未出清引发的故障锁闭阻止冲突进路；全段空闲后可人工复位。"""
    il.request_route(conn, "R-MAIN")
    for s, d in enumerate(["D0", "D1", "D2", "D3"]):
        il.report_event(conn, ev(s + 1, d, "occupy"))
    il.report_event(conn, ev(5, "D3", "clear"))  # 前段 S0/S1/S2 仍占用 => 故障
    inst = il.snapshot(conn)["instances"][-1]
    assert inst["status"] == "faulted"

    # 锁仍在：共用 S0/S3/侧防的 R-SIDING 被拒
    denied = il.request_route(conn, "R-SIDING")
    assert denied["decision"] == "denied"
    assert any(c["type"] == "section_locked" for c in denied["conflicts"])
    assert any(c["type"] == "flank_locked" for c in denied["conflicts"])

    # 前段仍占用，不能复位
    with pytest.raises(il.ClientError) as ei:
        il.reset_instance(conn, inst["id"])
    assert ei.value.code == "reset_blocked"

    # 全段出清空闲后人工复位成功，锁解除
    for s, d in enumerate(["D0", "D1", "D2"]):
        il.report_event(conn, ev(6 + s, d, "clear"))
    res = il.reset_instance(conn, inst["id"])
    assert res["reset"] is True
    snap = il.snapshot(conn)
    assert snap["instances"][-1]["status"] == "completed"
    assert [l for l in snap["locks"] if l["instance_id"] == inst["id"]] == []
    # 复位后冲突进路可放行
    assert il.request_route(conn, "R-SIDING")["decision"] == "permitted"


def test_last_clear_normal_completion_still_completes(conn, yard):
    """正常逐段出清：末段出清时无任何前段占用，正常完成、释放全部锁。"""
    il.request_route(conn, "R-MAIN")
    _full_run_s0_to_s3(conn)
    snap = il.snapshot(conn)
    assert snap["instances"][-1]["status"] == "completed"
    assert [l for l in snap["locks"] if l["route_id"] == "R-MAIN"] == []


def test_reoccupied_released_front_not_misjudged_on_last_clear(conn, yard):
    """前段 S0 已合法释放后，由外部检测再次报占用：末段 S3 出清时该段占用
    虽存在，但其锁已不属本实例，不得误判为本实例故障，进路应正常完成。"""
    il.request_route(conn, "R-MAIN")
    il.report_event(conn, ev(1, "D0", "occupy"))
    il.report_event(conn, ev(2, "D1", "occupy"))  # 推进到 S1；S0 仍占用，未释放
    il.report_event(conn, ev(3, "D0", "clear"))   # S0 出清；后继 S1 已占用 => 释放 S0
    il.report_event(conn, ev(4, "D2", "occupy"))  # 推进到 S2
    il.report_event(conn, ev(5, "D1", "clear"))   # S1 出清释放
    il.report_event(conn, ev(6, "D3", "occupy"))  # 推进到 S3（末段）
    il.report_event(conn, ev(7, "D2", "clear"))   # S2 出清释放
    # S0 早已合法释放；此刻外部检测再次报其占用（越序于本实例，但锁已不在）
    reocc = il.report_event(conn, ev(8, "D0", "occupy"))
    assert reocc["processed"][0]["state"]["event"] == "external_occupy"
    snap = il.snapshot(conn)
    assert not any(l["resource_id"] == "S0" for l in snap["locks"])

    # 末段出清：S0 虽占用但属已释放段的外部再占用 => 正常完成、无故障
    r = il.report_event(conn, ev(9, "D3", "clear"))
    p = r["processed"][0]
    assert p["fault"] is False
    assert p["state"]["event"] == "complete"
    assert p["state"]["external_occupied"] == ["S0"]
    snap = il.snapshot(conn)
    assert snap["instances"][-1]["status"] == "completed"
    assert [l for l in snap["locks"] if l["route_id"] == "R-MAIN"] == []


def test_last_clear_distinguishes_lingering_from_external_front(conn, yard):
    """混合场景：S0 已合法释放后被外部再占用，S1 锁仍属本实例且未出清；
    末段出清只把 S1 判为 lingering 故障，S0 记为 external，不误判。"""
    il.request_route(conn, "R-MAIN")
    il.report_event(conn, ev(1, "D0", "occupy"))
    il.report_event(conn, ev(2, "D1", "occupy"))
    il.report_event(conn, ev(3, "D0", "clear"))   # S0 合法释放
    il.report_event(conn, ev(4, "D2", "occupy"))  # 推进到 S2（S1 仍占用、锁保留）
    il.report_event(conn, ev(5, "D3", "occupy"))  # 推进到末段 S3（S1、S2 仍占用）
    il.report_event(conn, ev(6, "D2", "clear"))   # S2 出清释放；S1 仍占用且锁在
    il.report_event(conn, ev(7, "D0", "occupy"))  # 已释放的 S0 被外部再占用
    r = il.report_event(conn, ev(8, "D3", "clear"))
    p = r["processed"][0]
    assert p["fault"] is True
    assert p["state"]["lingering"] == ["S1"]
    assert p["state"]["external_occupied"] == ["S0"]
    snap = il.snapshot(conn)
    assert snap["instances"][-1]["status"] == "faulted"
    held = {l["resource_id"] for l in snap["locks"] if l["resource_type"] == "section"}
    assert "S1" in held and "S0" not in held  # S1 锁保留，S0 锁从未恢复


# ---------------- 只增与重启 ----------------
def test_logs_are_immutable(conn, yard):
    il.request_route(conn, "R-MAIN")
    il.report_event(conn, ev(1, "D0", "occupy"))
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE events SET kind='clear' WHERE seq=1")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM events WHERE seq=1")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE approvals SET decision='denied' WHERE approval_id=1")


def test_restart_state_persists_and_replay(conn, yard, tmp_path):
    il.request_route(conn, "R-MAIN")
    il.report_event(conn, ev(1, "D0", "occupy"))
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    conn.close()

    c2 = connect(path)
    snap = il.snapshot(c2)
    assert any(l["resource_id"] == "S0" for l in snap["locks"])
    assert snap["next_seq"] == 2
    rep = il.replay(c2, 0, 100)
    kinds = [d["kind"] for d in rep["items"]]
    assert "import" in kinds and "approval" in kinds and "event" in kinds
    c2.close()


def test_reimport_clears_runtime_but_keeps_sequence(conn, yard):
    il.request_route(conn, "R-MAIN")
    _full_run_s0_to_s3(conn)
    il.import_yard(conn, yard)  # 无活动实例，允许重导
    snap = il.snapshot(conn)
    assert snap["locks"] == []
    assert snap["next_seq"] == 9  # 8 条上报后下一序号为 9，序号不回退
