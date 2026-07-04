/*
 * Typhoon YARA Rules — OT Payload Detection
 * Vigil Typhoon Framework v1.0.0 — 2026-06-15
 * Author: Bo Shang — Trenchwork
 *
 * Covers: Modbus PLC kill, BACnet thermal kill, DNP3 pipeline burst,
 *         CIP auth bypass, CAN bus frame injection, ChimeraForge hardened variants
 *
 * ATT&CK: T0855 (Unauthorized Command), T0843 (Program Download),
 *         T0814 (DoS), T0884 (Modify Controller Parameters)
 */

rule Typhoon_Modbus_KineticStrike {
    meta:
        description = "Modbus TCP centrifuge kill chain"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "critical"
        attack = "T0855"
        protocol = "Modbus/TCP"
    strings:
        $mbap_hdr = { 00 00 00 00 00 06 01 }
        $write_mult = { 10 00 01 00 01 }
        $overspeed = { 1F 40 }
        $interlock_off = { 10 00 20 00 01 00 00 }
        $estop_off = { 05 00 00 00 00 }
        $kill_read = { 03 00 00 00 04 }
    condition:
        ($mbap_hdr at 0) and
        (($write_mult and $overspeed) or $interlock_off or $estop_off) and
        $kill_read
}

// ---- BACnet thermal kill ------------------------------------------------

rule Typhoon_BACnet_ThermalKill {
    meta:
        description = "BACnet/IP HVAC thermal kill — supply temp override, chiller disable"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "critical"
        attack = "T0884"
        protocol = "BACnet/IP"
    strings:
        $bvlc = { 81 }
        $npdu_bcast = { 01 20 FF FF 00 }
        $write_prop = { 0F }
        $supply_temp = { 05 00 00 01 00 55 }
        $chiller_off = { 04 00 00 01 00 00 91 01 00 }
        $alarm_suppress = { 04 00 00 03 00 C4 }
        $temp_60c = { 44 08 00 00 00 00 00 00 4E 40 }
    condition:
        ($bvlc in (0..4)) and $npdu_bcast and $write_prop and
        (($supply_temp and $temp_60c) or $chiller_off or $alarm_suppress)
}

// ---- DNP3 pipeline burst ------------------------------------------------

rule Typhoon_DNP3_PipelineBurst {
    meta:
        description = "DNP3 pipeline pressure override — fragmented Direct Operate"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "critical"
        attack = "T0855"
        protocol = "DNP3"
    strings:
        $dnp3_start = { 05 64 }
        $ctrl_fir_fin = { C0 }
        $direct_op = { 0D }
        $pressure_grp = { 29 03 }
        $safety_valve = { 29 04 01 01 00 00 00 00 }
        $psi_5k = { 88 13 }
        $alarm_thresh = { 29 05 01 01 }
    condition:
        ($dnp3_start at 0) and $ctrl_fir_fin and $direct_op and
        ($pressure_grp or $safety_valve or $psi_5k or $alarm_thresh)
}

// ---- CIP / Rockwell auth bypass (CVE-2021-22681) ------------------------

rule Typhoon_CIP_AuthBypass_CVE_2021_22681 {
    meta:
        description = "Rockwell CIP auth bypass CVE-2021-22681 — shared private key exploit"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "critical"
        attack = "T0859,T0843"
        cve = "CVE-2021-22681"
        protocol = "CIP/ENIP"
    strings:
        $enip_sess = { 65 00 04 00 }
        $forward_open = { 54 00 }
        $auth_token = { A1 00 00 }
        $tag_write = { 4D 00 }
        $tag_read = { 4C 00 }
        $firmware_dl = { 50 00 0A 00 }
        $key_ref = "RaLicSec" ascii wide
    condition:
        ($enip_sess or $forward_open) and
        (($auth_token and ($tag_write or $tag_read)) or $firmware_dl or $key_ref)
}

// ---- CAN bus frame injection / J1939 spoof ------------------------------

rule Typhoon_CANBus_FrameInjection {
    meta:
        description = "CAN bus frame injection — high-priority flood, NMT reset, J1939 spoof"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "critical"
        attack = "T0855,T0814"
        protocol = "CAN"
    strings:
        $id_zero = { 00 00 00 00 }
        $nmt_reset = { 00 00 81 }
        $j1939_dm1 = { 18 FE CA }
        $fmi_short = { 01 00 }
        $sdo_safety = { 23 20 00 }
        $addr_conflict = { 18 EE FF 00 }
        $cansend = "cansend" ascii wide
        $socketcan = "SocketCAN" ascii wide
    condition:
        any of ($cansend, $socketcan) and
        any of ($id_zero, $nmt_reset, $j1939_dm1, $sdo_safety, $addr_conflict, $fmi_short)
}

// ---- ChimeraForge universal mutation fingerprint ------------------------

rule Typhoon_ChimeraForge_Universal {
    meta:
        description = "Universal ChimeraForge mutation fingerprint — hardened OT payloads"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "high"
        attack = "T1027"
    strings:
        $cf_prefix = "CF-" ascii wide
        $xor_loop = { 31 C0 48 39 C8 7F }
        $nop_sled_8 = { 90 90 90 90 90 90 90 90 }
        $dead_jump = { EB [08-20] [00-FF]{6,24} }
        $self_del = "self_cleanup" ascii wide
        $log_tamper = "log_tamper" ascii wide
        $ts_spoof = "ts_spoof" ascii wide
        $proc_name = "[kworker" ascii wide
    condition:
        3 of them
}

// ---- ChimeraForge multi-stage transport --------------------------------

rule Typhoon_ChimeraForge_Transport_Stager {
    meta:
        description = "ChimeraForge multi-stage C2 stager — DNS/ICMP/HTTPS transport"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "high"
        attack = "T1105"
    strings:
        $dns_txt = { 64 69 67 20 54 58 54 }
        $http_s1 = "GET /s1 HTTP/1.1" ascii wide
        $icmp_echo = { 08 00 [00-FF]{2} 00 }
        $fetch_cmd = "FETCH" ascii wide
        $connector = "S1:" ascii wide
    condition:
        any of them
}

// ---- AWS exploitation payloads ------------------------------------------

rule Typhoon_AWS_ReconPayload {
    meta:
        description = "AWS reconnaissance — EC2 describe, S3 list, IAM enumerate"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "high"
        attack = "T1526"
        protocol = "AWS API"
    strings:
        $ec2_desc = "describe-instances" ascii
        $s3_list = "list-buckets" ascii
        $iam_list = "list-users" ascii
        $iam_pol = "list-attached-user-policies" ascii
        $sec_collect = "aws_secret_collector" ascii wide
        $privesc = "iam_privesc" ascii wide
    condition:
        2 of them
}

rule Typhoon_AWS_LateralCredHarvest {
    meta:
        description = "AWS lateral movement + credential harvesting payload"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "critical"
        attack = "T1552,T1021"
        protocol = "AWS API"
    strings:
        $cred_harvest = "cred_harvest" ascii wide
        $lateral = "lateral_move" ascii wide
        $sts_token = "get-session-token" ascii
        $ec2_ssm = "send-command" ascii
        $lambda_invoke = "invoke" ascii
    condition:
        2 of them
}

// ---- Persistence implants -----------------------------------------------

rule Typhoon_Persistence_Implants {
    meta:
        description = "OT persistence implants — Modbus, BACnet, DNP3, CAN bus"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "critical"
        attack = "T1543.003,T0855"
    strings:
        $modbus_persist = "persist_register" ascii wide
        $bacnet_schedule = "schedule_obj" ascii wide
        $dnp3_config = "config_point" ascii wide
        $can_implant = "can_implant" ascii wide
        $persist_desc = "PERSISTENCE_TARGETS" ascii wide
    condition:
        2 of them
}

// ---- C2 beacon / covert ops ---------------------------------------------

rule Typhoon_C2_CovertOps_Beacon {
    meta:
        description = "C2 covert operations beacon — multichannel, exfiltration"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "critical"
        attack = "T1071,T1041"
    strings:
        $beacon = "multichannel_beacon" ascii wide
        $dns_exfil = ".example.com" ascii
        $https_c2 = "c2.ex" ascii
        $strike_orch = "strike_orchestrator" ascii wide
        $target_acq = "target_acquisition" ascii wide
    condition:
        2 of them
}

// ---- Generic hardened payload fingerprint -------------------------------

rule Typhoon_HardenedPayload_Generic {
    meta:
        description = "Generic hardened OT payload — evasion, anti-forensics, C2 transport"
        author = "Vigil Typhoon"
        date = "2026-06-15"
        severity = "high"
        attack = "T1027,T1070,T1105"
    strings:
        $hardened_class = "HardenedModbusKill" ascii wide
        $hardened_bac = "HardenedBACnetKill" ascii wide
        $hardened_dnp = "HardenedDNP3Burst" ascii wide
        $strike_id = "HARD-" ascii wide
        $af_flag = "anti_forensics" ascii wide
        $evasion = "xor_encrypt" ascii wide
        $self_del = "self_cleanup" ascii wide
    condition:
        3 of them
}
