/*
** wireshark-topdog-dissector.c - Wireshark dissector for the
**	Marvell TopDog 88W8362 USB protocol.
** Authors: Andrew D'Addesio <andrew@fatbag.net>
** License: Public domain (no warranties)
** Compile: gcc -Wall -ansi -Os -g0 -s -shared -fPIC
**	$(pkg-config --cflags wireshark) -o wireshark-topdog-dissector.so
**	wireshark-topdog-dissector.c $(pkg-config --libs wireshark)
** Install: cp -v wireshark-topdog-dissector.so ~/.wireshark/plugins
** Use: export WIRESHARK_PLUGIN_DIR=~/.wireshark/plugins && wireshark-qt
**
** Note: At the present time, the 802.11 layer output by this dissector is
** broken. Specifically we need a way to tell the Wireshark wlan dissector that
** the 802.11 header is *always* the 4-address format and *never* has the QoS
** Control field. (Maybe we need to produce a patch for packet-ieee802.11.c.)
*/
#include <stdio.h>
#include <gmodule.h>
#include <wireshark/config.h>
#include <wireshark/epan/packet.h>
#include <wireshark/epan/dissectors/packet-usb.h>

/* Symbols exported by this library */
G_MODULE_EXPORT const gchar version[] = "0";
G_MODULE_EXPORT void plugin_register(void);
G_MODULE_EXPORT void plugin_reg_handoff(void);

/* TopDog protocol handles */
/* static dissector_handle_t topdog_handle = NULL; */
static dissector_handle_t wlan_handle = NULL;
static int proto_topdog = -1;
static int hf_pdu_type = -1;
static int hf_fw_seq_num = -1;
static int hf_fw_dest_addr = -1;
static int hf_fw_data_size = -1;
static int hf_fw_header_checksum = -1;
static int hf_fw_data = -1;
static int hf_fw_data_checksum = -1;
static int hf_tag = -1;
static int hf_transfer_len = -1;
static int hf_fun_flag = -1;
static int hf_data_residue = -1;
static int hf_status = -1;
static int hf_cmd_wrapper_len = -1;
static int hf_cmd = -1;
static int hf_cmd_len = -1;
static int hf_cmd_seq_num = -1;
static int hf_cmd_result = -1;
static int hf_cmd_body = -1;
static int hf_wcb_ctrl_stat = -1;
static int hf_wcb_tx_pri = -1;
static int hf_wcb_tx_frag_count = -1;
static int hf_wcb_qos_ctrl = -1;
static int hf_wcb_pkt_ptr = -1;
static int hf_wcb_pkt_len = -1;
static int hf_wcb_dest_mac = -1;
static int hf_wcb_next_ptr = -1;
static int hf_wcb_rate_info = -1;
static int hf_wcb_reserved = -1;
static int hf_rxpd_rx_ctrl = -1;
static int hf_rxpd_rssi = -1;
static int hf_rxpd_channel = -1;
static int hf_rxpd_noise_lvl = -1;
static int hf_rxpd_pkt_len = -1;
static int hf_rxpd_next_ptr = -1;
static int hf_rxpd_qos_ctrl = -1;
static int hf_rxpd_rxpd_ctrl = -1;
static int hf_rxpd_rx_rate_info = -1;
static int hf_rxpd_tx_rate_info = -1;
static int hf_qos_ctrl_tid = -1;
static int hf_qos_ctrl_eos = -1;
static int hf_qos_ctrl_ack_policy = -1;
static int hf_qos_ctrl_amsdu_present = -1;
static int hf_qos_ctrl_queue_size = -1;
static int hf_rate_info_ht_mode = -1;
static int hf_rate_info_short_gi = -1;
static int hf_rate_info_bandwidth = -1;
static int hf_rate_info_mcs = -1;
static int hf_rate_info_adv_coding = -1;
static int hf_rate_info_ant_select = -1;
static int hf_rate_info_active_subchannels = -1;
static int hf_rate_info_short_preamble = -1;
static int hf_rxpd_ctrl_is_ampdu = -1;
static int hf_rxpd_ctrl_owner = -1;
static int hf_rxpd_ctrl_decrypt_error = -1;
static int hf_rxpd_ctrl_error_type = -1;
static int hf_rxpd_ctrl_key_index = -1;
static int hf_rxpd_ctrl_reserved = -1;
static int hf_wlan_pkt = -1;
static gint ett_topdog = -1;
static gint ett_qos_ctrl = -1;
static gint ett_rate_info = -1;
static gint ett_rxpd_ctrl = -1;

static const value_string topdog_types[] = {
	{0x00000000, "FW_RESPONSE"},
	{0x00000001, "FW_SET"},
	{0x00000004, "FW_SET_AND_EXECUTE"},
	{0x4D434257, "MCBW"},
	{0x4D435357, "MCSW"},
	{0x4D545844, "MTXD"},
	{0x4D525844, "MRXD"},
	{0, NULL}
};

static const value_string cmd_types[] = {
	{0x0000, "CMD_NONE Request"},
	{0x8000, "CMD_NONE Response"},
	{0x0001, "CMD_CODE_DNLD Request"},
	{0x8001, "CMD_CODE_DNLD Response"},
	{0x0003, "CMD_GET_HW_SPEC Request"},
	{0x8003, "CMD_GET_HW_SPEC Response"},
	{0x0004, "CMD_SET_HW_SPEC Request"},
	{0x8004, "CMD_SET_HW_SPEC Response"},
	{0x0010, "CMD_MAC_MULTICAST_ADR Request"},
	{0x8010, "CMD_MAC_MULTICAST_ADR Response"},
	{0x0014, "CMD_GET_STAT Request"},
	{0x8014, "CMD_GET_STAT Response"},
	{0x001a, "CMD_BBP_REG_ACCESS Request"},
	{0x801a, "CMD_BBP_REG_ACCESS Response"},
	{0x001c, "CMD_RADIO_CONTROL Request"},
	{0x801c, "CMD_RADIO_CONTROL Response"},
	{0x001d, "CMD_802_11_RF_CHANNEL Request"},
	{0x801d, "CMD_802_11_RF_CHANNEL Response"},
	{0x001e, "CMD_RF_TX_POWER Request"},
	{0x801e, "CMD_RF_TX_POWER Response"},
	{0x001f, "CMD_TX_POWER Request"},
	{0x801f, "CMD_TX_POWER Response"},
	{0x0020, "CMD_RF_ANTENNA Request"},
	{0x8020, "CMD_RF_ANTENNA Response"},
	{0x0050, "CMD_BROADCAST_SSID_ENABLE Request"},
	{0x8050, "CMD_BROADCAST_SSID_ENABLE Response"},
	{0x0100, "CMD_SET_BEACON Request"},
	{0x8100, "CMD_SET_BEACON Response"},
	{0x0107, "CMD_SET_PRE_SCAN Request"},
	{0x8107, "CMD_SET_PRE_SCAN Response"},
	{0x0108, "CMD_SET_POST_SCAN Request"},
	{0x8108, "CMD_SET_POST_SCAN Response"},
	{0x010a, "CMD_SET_RF_CHANNEL Request"},
	{0x810a, "CMD_SET_RF_CHANNEL Response"},
	{0x010d, "CMD_SET_AID Request"},
	{0x810d, "CMD_SET_AID Response"},
	{0x010e, "CMD_SET_INFRA_MODE Request"},
	{0x810e, "CMD_SET_INFRA_MODE Response"},
	{0x010f, "CMD_SET_G_PROTECT_FLAG Request"},
	{0x810f, "CMD_SET_G_PROTECT_FLAG Response"},
	{0x0110, "CMD_SET_RATE Request"},
	{0x8110, "CMD_SET_RATE Response"},
	{0x0111, "CMD_SET_FINALIZE_JOIN Request"},
	{0x8111, "CMD_SET_FINALIZE_JOIN Response"},
	{0x0113, "CMD_RTS_THRESHOLD Request"},
	{0x8113, "CMD_RTS_THRESHOLD Response"},
	{0x0114, "CMD_SET_SLOT Request"},
	{0x8114, "CMD_SET_SLOT Response"},
	{0x0115, "CMD_SET_EDCA_PARAMS Request"},
	{0x8115, "CMD_SET_EDCA_PARAMS Response"},
	{0x0116, "CMD_802_11_BOOST_MODE Request"},
	{0x8116, "CMD_802_11_BOOST_MODE Response"},
	{0x0118, "CMD_PARENT_TSF Request"},
	{0x8118, "CMD_PARENT_TSF Response"},
	{0x0119, "CMD_RPI_DENSITY Request"},
	{0x8119, "CMD_RPI_DENSITY Response"},
	{0x011a, "CMD_CCA_BUSY_FRACTION Request"},
	{0x811a, "CMD_CCA_BUSY_FRACTION Response"},
	{0x011b, "CMD_LED_GET_STATE Request"},
	{0x811b, "CMD_LED_GET_STATE Response"},
	{0x011c, "CMD_LED_SET_STATE Request"},
	{0x811c, "CMD_LED_SET_STATE Response"},
	{0x011d, "CMD_STOP_BEACON Request"},
	{0x811d, "CMD_STOP_BEACON Response"},
	{0x011e, "CMD_CCA_GET_BBU_NOISE Request"},
	{0x811e, "CMD_CCA_GET_BBU_NOISE Response"},
	{0x0120, "CMD_802_11H_DETECT_RADAR Request"},
	{0x8120, "CMD_802_11H_DETECT_RADAR Response"},
	{0x0121, "CMD_802_11H_QUERY_DETECT_INFO Request"},
	{0x8121, "CMD_802_11H_QUERY_DETECT_INFO Response"},
	{0x0122, "CMD_802_11_TX_POWER Request"},
	{0x8122, "CMD_802_11_TX_POWER Response"},
	{0x0123, "CMD_SET_WMM_MODE Request"},
	{0x8123, "CMD_SET_WMM_MODE Response"},
	{0x0124, "CMD_HT_GUARD_INTERVAL Request"},
	{0x8124, "CMD_HT_GUARD_INTERVAL Response"},
	{0x0125, "CMD_MIMO_CONFIG Request"},
	{0x8125, "CMD_MIMO_CONFIG Response"},
	{0x0126, "CMD_USE_FIXED_RATE Request"},
	{0x8126, "CMD_USE_FIXED_RATE Response"},
	{0x0127, "CMD_SET_REGION_POWER Request"},
	{0x8127, "CMD_SET_REGION_POWER Response"},
	{0x0128, "CMD_SET_RTS_CTS_MODE Request"},
	{0x8128, "CMD_SET_RTS_CTS_MODE Response"},
	{0x0129, "CMD_SET_BT_PRIORITY Request"},
	{0x8129, "CMD_SET_BT_PRIORITY Response"},
	{0x0130, "CMD_SQ_RAM_MAP Request"},
	{0x8130, "CMD_SQ_RAM_MAP Response"},
	{0x0132, "? Request"},
	{0x8132, "? Response"},
	{0x0150, "CMD_ENABLE_SNIFFER Request"},
	{0x8150, "CMD_ENABLE_SNIFFER Response"},
	{0x01ff, "CMD_SET_PASSTHRU Request"},
	{0x81ff, "CMD_SET_PASSTHRU Response"},
	{0x0201, "CMD_SET_EAPOL_START Request"},
	{0x8201, "CMD_SET_EAPOL_START Response"},
	{0x0202, "CMD_SET_MAC_ADDR Request"},
	{0x8202, "CMD_SET_MAC_ADDR Response"},
	{0x0203, "CMD_SET_RATEADAPT_MODE Request"},
	{0x8203, "CMD_SET_RATEADAPT_MODE Response"},
	{0x0204, "CMD_SET_LINKADAPT_CS_MODE Request"},
	{0x8204, "CMD_SET_LINKADAPT_CS_MODE Response"},
	{0x0205, "CMD_GET_WATCHDOG_BITMAP Request"},
	{0x8205, "CMD_GET_WATCHDOG_BITMAP Response"},
	{0x0206, "CMD_DEL_MAC_ADDR Request"},
	{0x8206, "CMD_DEL_MAC_ADDR Response"},
	{0x0210, "? Request"},
	{0x8210, "? Response"},
	{0x0211, "CMD_802_11_TX_POWER_LEVEL Request"},
	{0x8211, "CMD_802_11_TX_POWER_LEVEL Response"},
	{0x0212, "? Request"},
	{0x8212, "? Response"},
	{0x0800, "CMD_SET_DRIVER_READY Request"},
	{0x8800, "CMD_SET_DRIVER_READY Response"},
	{0x1100, "CMD_BSS_START Request"},
	{0x9100, "CMD_BSS_START Response"},
	{0x1101, "CMD_AP_BEACON Request"},
	{0x9101, "CMD_AP_BEACON Response"},
	{0x1103, "CMD_UPDATE_TIM Request"},
	{0x9103, "CMD_UPDATE_TIM Response"},
	{0x1110, "CMD_WDS_ENABLE Request"},
	{0x9110, "CMD_WDS_ENABLE Response"},
	{0x1111, "CMD_SET_NEW_STN Request"},
	{0x9111, "CMD_SET_NEW_STN Response"},
	{0x1113, "CMD_SET_BURST_MODE Request"},
	{0x9113, "CMD_SET_BURST_MODE Response"},
	{0x1122, "CMD_UPDATE_ENCRYPTION Request"},
	{0x9122, "CMD_UPDATE_ENCRYPTION Response"},
	{0x1123, "CMD_UPDATE_STADB Request"},
	{0x9123, "CMD_UPDATE_STADB Response"},
	{0x1124, "CMD_SET_LOOPBACK_MODE Request"},
	{0x9124, "CMD_SET_LOOPBACK_MODE Response"},
	{0x1125, "CMD_BASTREAM Request"},
	{0x9125, "CMD_BASTREAM Response"},
	{0, NULL}
};

static const value_string bandwidth_types[] = {
	{0, "20 MHz"},
	{1, "40 MHz"},
	{0, NULL}
};

static const value_string adv_coding_types[] = {
	{0, "None"},
	{1, "LDPC"},
	{2, "Reed-Solomon"},
	{0, NULL}
};

static const value_string ant_select_types[] = {
	{0, "None"},
	{1, "Ant0"},
	{2, "Ant1"},
	{3, "Ant0, Ant1"},
	{0, NULL}
};

static const value_string active_subchannels_types[] = {
	{0, "Lower"},
	{1, "Upper"},
	{2, "Lower and Upper"},
	{0, NULL}
};

static const value_string rxpd_ctrl_owner_types[] = {
	{0, "Firmware"},
	{1, "Host"},
	{0, NULL}
};

static const value_string rxpd_ctrl_error_types[] = {
	{0, "ICV"},
	{1, "MIC"},
	{0, NULL}
};

static hf_register_info hf[] = {
	{
		&hf_pdu_type,
		{
			"PDU Type", "topdog.type",
			FT_UINT32, BASE_HEX,
			VALS(topdog_types), 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_fw_seq_num,
		{
			"Sequence Number", "topdog.fw_seq_num",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_fw_dest_addr,
		{
			"Dest Address", "topdog.fw_dest_addr",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_fw_data_size,
		{
			"Data Size", "topdog.fw_data_size",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_fw_header_checksum,
		{
			"Header Checksum", "topdog.fw_header_checksum",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_fw_data,
		{
			"Data", "topdog.fw_data",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_fw_data_checksum,
		{
			"Data Checksum", "topdog.fw_data_checksum",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_tag,
		{
			"Tag", "topdog.tag",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_transfer_len,
		{
			"Transfer Len", "topdog.transfer_len",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_fun_flag,
		{
			"Function Flag", "topdog.fun_flag",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_data_residue,
		{
			"Data Residue", "topdog.data_residue",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_status,
		{
			"Status", "topdog.status",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_cmd_wrapper_len,
		{
			"Command Wrapper Length", "topdog.cmd_wrapper_len",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_cmd,
		{
			"Command", "topdog.cmd",
			FT_UINT16, BASE_HEX,
			VALS(cmd_types), 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_cmd_len,
		{
			"Length", "topdog.cmd_len",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_cmd_seq_num,
		{
			"Sequence Number", "topdog.cmd_seq_num",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_cmd_result,
		{
			"Result", "topdog.cmd_result",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_cmd_body,
		{
			"Body", "topdog.cmd_body",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_wcb_ctrl_stat,
		{
			"Control Status", "topdog.wcb_ctrl_stat",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_wcb_tx_pri,
		{
			"TX Priority", "topdog.wcb_tx_pri",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_wcb_tx_frag_count,
		{
			"TX Fragment Count", "topdog.wcb_tx_frag_count",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_wcb_qos_ctrl,
		{
			"QoS Control", "topdog.wcb_qos_ctrl",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_wcb_pkt_ptr,
		{
			"Packet Pointer", "topdog.wcb_pkt_ptr",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_wcb_pkt_len,
		{
			"Packet Length", "topdog.wcb_pkt_len",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_wcb_dest_mac,
		{
			"Dest MAC Address", "topdog.wcb_dest_mac",
			FT_ETHER, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_wcb_next_ptr,
		{
			"Next WCB Pointer", "topdog.wcb_next_ptr",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_wcb_rate_info,
		{
			"Rate Info", "topdog.wcb_rate_info",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_wcb_reserved,
		{
			"Reserved", "topdog.wcb_reserved",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_rx_ctrl,
		{
			"RX Control", "topdog.rxpd_rx_ctrl",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_rssi,
		{
			"RSSI", "topdog.rxpd_rssi",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_channel,
		{
			"Channel", "topdog.rxpd_channel",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_noise_lvl,
		{
			"Noise Level", "topdog.rxpd_noise_lvl",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_pkt_len,
		{
			"Packet Length", "topdog.pkt_len",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_next_ptr,
		{
			"Next RxPD Pointer", "topdog.next_rxpd_ptr",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_qos_ctrl,
		{
			"QoS Control", "topdog.qos_ctrl",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_rxpd_ctrl,
		{
			"RxPD Control", "topdog.rxpd_rxpd_ctrl",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_rx_rate_info,
		{
			"RX Rate Info", "topdog.rxpd_rx_rate_info",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_tx_rate_info,
		{
			"TX Rate Info", "topdog.rxpd_tx_rate_info",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL
		}
	},
	{
		&hf_qos_ctrl_tid,
		{
			"TID", "topdog.qos_ctrl.tid",
			FT_UINT16, BASE_HEX,
			NULL, 0x000f,
			NULL, HFILL
		}
	},
	{
		&hf_qos_ctrl_eos,
		{
			"EOS", "topdog.qos_ctrl.eos",
			FT_BOOLEAN, 16,
			NULL, 0x0010,
			NULL, HFILL
		}
	},
	{
		&hf_qos_ctrl_ack_policy,
		{
			"ACK Policy", "topdog.qos_ctrl.ack_policy",
			FT_UINT16, BASE_HEX,
			NULL, 0x0060,
			NULL, HFILL
		}
	},
	{
		&hf_qos_ctrl_amsdu_present,
		{
			"AMSDU Present", "topdog.qos_ctrl.amsdu_present",
			FT_BOOLEAN, 16,
			NULL, 0x0080,
			NULL, HFILL
		}
	},
	{
		&hf_qos_ctrl_queue_size,
		{
			"Queue Size", "topdog.qos_ctrl.queue_size",
			FT_UINT16, BASE_HEX,
			NULL, 0xff00,
			NULL, HFILL
		}
	},
	{
		&hf_rate_info_ht_mode,
		{
			"High-Throughput Mode", "topdog.rate_info.ht_mode",
			FT_BOOLEAN, 16,
			NULL, 0x0001,
			NULL, HFILL
		}
	},
	{
		&hf_rate_info_short_gi,
		{
			"Short Guard Interval", "topdog.rate_info.short_gi",
			FT_BOOLEAN, 16,
			NULL, 0x0002,
			NULL, HFILL
		}
	},
	{
		&hf_rate_info_bandwidth,
		{
			"Bandwidth", "topdog.rate_info.bandwidth",
			FT_UINT16, BASE_HEX,
			VALS(bandwidth_types), 0x0004,
			NULL, HFILL
		}
	},
	{
		&hf_rate_info_mcs,
		{
			"MCS Index", "topdog.rate_info.mcs",
			FT_UINT16, BASE_HEX,
			NULL, 0x01f8,
			NULL, HFILL
		}
	},
	{
		&hf_rate_info_adv_coding,
		{
			"Advanced Coding", "topdog.rate_info.adv_coding",
			FT_UINT16, BASE_HEX,
			VALS(adv_coding_types), 0x0600,
			NULL, HFILL
		}
	},
	{
		&hf_rate_info_ant_select,
		{
			"Antenna Select", "topdog.rate_info.ant_select",
			FT_UINT16, BASE_HEX,
			VALS(ant_select_types), 0x1800,
			NULL, HFILL
		}
	},
	{
		&hf_rate_info_active_subchannels,
		{
			"Active Subchannels", "topdog.rate_info.active_subchannels",
			FT_UINT16, BASE_HEX,
			VALS(active_subchannels_types), 0x6000,
			NULL, HFILL
		}
	},
	{
		&hf_rate_info_short_preamble,
		{
			"Short Preamble", "topdog.rate_info.short_preamble",
			FT_BOOLEAN, 16,
			NULL, 0x8000,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_ctrl_is_ampdu,
		{
			"Is AMPDU Packet", "topdog.rxpd_ctrl.is_ampdu",
			FT_BOOLEAN, 16,
			NULL, 0x0001,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_ctrl_owner,
		{
			"Owner", "topdog.rxpd_ctrl.owner",
			FT_UINT16, BASE_HEX,
			VALS(rxpd_ctrl_owner_types), 0x0002,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_ctrl_decrypt_error,
		{
			"Decryption Error", "topdog.rxpd_ctrl.decrypt_error",
			FT_BOOLEAN, 16,
			NULL, 0x0004,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_ctrl_error_type,
		{
			"Error Type", "topdog.rxpd_ctrl.error_type",
			FT_UINT16, BASE_HEX,
			VALS(rxpd_ctrl_error_types), 0x0008,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_ctrl_key_index,
		{
			"Key Index", "topdog.rxpd_ctrl.key_index",
			FT_UINT16, BASE_HEX,
			NULL, 0x0030,
			NULL, HFILL
		}
	},
	{
		&hf_rxpd_ctrl_reserved,
		{
			"Reserved", "topdog.rxpd_ctrl.reserved",
			FT_UINT16, BASE_HEX,
			NULL, 0xffc0,
			NULL, HFILL
		}
	},
	{
		&hf_wlan_pkt,
		{
			"802.11 packet data", "topdog.wlan_pkt",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL
		}
	}
};

static const int *qos_ctrl_flags[] = {
	&hf_qos_ctrl_tid,
	&hf_qos_ctrl_eos,
	&hf_qos_ctrl_ack_policy,
	&hf_qos_ctrl_amsdu_present,
	&hf_qos_ctrl_queue_size,
	NULL
};

static const int *rate_info_flags[] = {
	&hf_rate_info_ht_mode,
	&hf_rate_info_short_gi,
	&hf_rate_info_bandwidth,
	&hf_rate_info_mcs,
	&hf_rate_info_adv_coding,
	&hf_rate_info_ant_select,
	&hf_rate_info_active_subchannels,
	&hf_rate_info_short_preamble,
	NULL
};

static const int *rxpd_ctrl_flags[] = {
	&hf_rxpd_ctrl_is_ampdu,
	&hf_rxpd_ctrl_owner,
	&hf_rxpd_ctrl_decrypt_error,
	&hf_rxpd_ctrl_error_type,
	&hf_rxpd_ctrl_key_index,
	&hf_rxpd_ctrl_reserved,
	NULL
};

static gint *ett_list[] = {
	&ett_topdog,
	&ett_qos_ctrl,
	&ett_rate_info,
	&ett_rxpd_ctrl
};

static void dissect_pdu(proto_tree *tree, tvbuff_t *tvb, guint32 offset, packet_info *pinfo);

static void dissect_fw_type_0(proto_tree *tree, tvbuff_t *tvb, guint32 offset, packet_info *pinfo)
{
	proto_tree_add_item(tree, hf_pdu_type, tvb, offset+0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_fw_seq_num, tvb, offset+4, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_fw_type_1_4(proto_tree *tree, tvbuff_t *tvb, guint32 offset, packet_info *pinfo)
{
	/* TODO: Verify checksums using crc32_ccitt_tvb_offset_seed. */
	guint32 data_size = tvb_get_letohl(tvb, offset+8);

	proto_tree_add_item(tree, hf_pdu_type, tvb, offset+0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_fw_dest_addr, tvb, offset+4, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_fw_data_size, tvb, offset+8, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_fw_header_checksum, tvb, offset+12, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_fw_data, tvb, offset+16, data_size, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_fw_data_checksum, tvb, offset+16+data_size, 4, ENC_BIG_ENDIAN);
}

static void dissect_topdog_mcbw(proto_tree *tree, tvbuff_t *tvb, guint32 offset, packet_info *pinfo)
{
	guint16 cmd_len = tvb_get_letohs(tvb, offset+14);

	proto_tree_add_item(tree, hf_pdu_type, tvb, offset+0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_tag, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_transfer_len, tvb, offset+6, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_fun_flag, tvb, offset+8, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd_wrapper_len, tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd, tvb, offset+12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd_len, tvb, offset+14, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd_seq_num, tvb, offset+16, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd_result, tvb, offset+18, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd_body, tvb, offset+20, cmd_len-8, ENC_LITTLE_ENDIAN);
}

static void dissect_topdog_mcsw(proto_tree *tree, tvbuff_t *tvb, guint32 offset, packet_info *pinfo)
{
	guint16 cmd_len = tvb_get_letohs(tvb, offset+14);

	proto_tree_add_item(tree, hf_pdu_type, tvb, offset+0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_tag, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_data_residue, tvb, offset+6, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_status, tvb, offset+8, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd_wrapper_len, tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd, tvb, offset+12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd_len, tvb, offset+14, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd_seq_num, tvb, offset+16, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd_result, tvb, offset+18, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_cmd_body, tvb, offset+20, cmd_len-8, ENC_LITTLE_ENDIAN);
}

static void dissect_topdog_mtxd(proto_tree *tree, tvbuff_t *tvb, guint32 offset, packet_info *pinfo)
{
	guint16 pkt_len = tvb_get_letohs(tvb, offset+14);
	guint32 wcb_next_ptr = tvb_get_letohl(tvb, offset+22);
	guint16 payload_len;

	proto_tree_add_item(tree, hf_pdu_type, tvb, offset+0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_wcb_ctrl_stat, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_wcb_tx_pri, tvb, offset+6, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_wcb_tx_frag_count, tvb, offset+7, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, offset+8, hf_wcb_qos_ctrl, ett_qos_ctrl, qos_ctrl_flags, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_wcb_pkt_ptr, tvb, offset+10, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_wcb_pkt_len, tvb, offset+14, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_wcb_dest_mac, tvb, offset+16, 6, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_wcb_next_ptr, tvb, offset+22, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, offset+26, hf_wcb_rate_info, ett_rate_info, rate_info_flags, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_wcb_reserved, tvb, offset+28, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_wlan_pkt, tvb, offset+32, pkt_len, ENC_LITTLE_ENDIAN);

	payload_len = tvb_get_letohs(tvb, offset+32);
	call_dissector(wlan_handle, tvb_new_subset_length(tvb, offset+34, payload_len+30), pinfo, proto_tree_get_parent_tree(tree));

	if (wcb_next_ptr != 0)
		return dissect_pdu(tree, tvb, offset + wcb_next_ptr, pinfo);
}

static void dissect_topdog_mrxd(proto_tree *tree, tvbuff_t *tvb, guint32 offset, packet_info *pinfo)
{
	guint16 pkt_len = tvb_get_letohs(tvb, offset+8);
	guint16 rxpd_next_ptr = tvb_get_letohs(tvb, offset+10);

	proto_tree_add_item(tree, hf_pdu_type, tvb, offset+0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_rxpd_rx_ctrl, tvb, offset+4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_rxpd_rssi, tvb, offset+5, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_rxpd_channel, tvb, offset+6, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_rxpd_noise_lvl, tvb, offset+7, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_rxpd_pkt_len, tvb, offset+8, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_rxpd_next_ptr, tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, offset+12, hf_rxpd_qos_ctrl, ett_qos_ctrl, qos_ctrl_flags, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, offset+14, hf_rxpd_rxpd_ctrl, ett_rxpd_ctrl, rxpd_ctrl_flags, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, offset+16, hf_rxpd_rx_rate_info, ett_rate_info, rate_info_flags, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, offset+18, hf_rxpd_tx_rate_info, ett_rate_info, rate_info_flags, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_wlan_pkt, tvb, offset+20, pkt_len, ENC_LITTLE_ENDIAN);

	pkt_len = tvb_get_letohs(tvb, offset+20);
	call_dissector(wlan_handle, tvb_new_subset_length(tvb, offset+22, pkt_len-2), pinfo, proto_tree_get_parent_tree(tree));

	if (rxpd_next_ptr != 0)
		return dissect_pdu(tree, tvb, offset + rxpd_next_ptr, pinfo);
}

static void dissect_pdu(proto_tree *tree, tvbuff_t *tvb, guint32 offset, packet_info *pinfo)
{
	guint32 pdu_type;

	if (offset > 0xffff)
		return;

	pdu_type = tvb_get_letohl(tvb, offset);

	switch (pdu_type) {
	case 0: dissect_fw_type_0(tree, tvb, offset, pinfo); break;
	case 1: case 4: dissect_fw_type_1_4(tree, tvb, offset, pinfo); break;
	case 0x4D434257: dissect_topdog_mcbw(tree, tvb, offset, pinfo); break;
	case 0x4D435357: dissect_topdog_mcsw(tree, tvb, offset, pinfo); break;
	case 0x4D545844: dissect_topdog_mtxd(tree, tvb, offset, pinfo); break;
	case 0x4D525844: dissect_topdog_mrxd(tree, tvb, offset, pinfo); break;
	}
}

static int dissect_topdog(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, void *data)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TOPDOG");

	if (tree) {
		proto_item *topdog_item = NULL;
		proto_tree *topdog_tree = NULL;

		topdog_item = proto_tree_add_item(tree, proto_topdog, tvb, 0, -1, ENC_NA);
		topdog_tree = proto_item_add_subtree(topdog_item, ett_topdog);

		dissect_pdu(topdog_tree, tvb, 0, pinfo);
	}

	return tvb_captured_length(tvb);
}

static gboolean
dissect_topdog_bulk_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	usb_conv_info_t *usb_conv_info = (usb_conv_info_t *)data;
	const guint8 mcbw[] = {0x57, 0x42, 0x43, 0x4D};
	const guint8 mcsw[] = {0x57, 0x53, 0x43, 0x4D};
	const guint8 mtxd[] = {0x44, 0x58, 0x54, 0x4D};
	const guint8 mrxd[] = {0x44, 0x58, 0x52, 0x4D};

	if (usb_conv_info != NULL
		&& usb_conv_info->deviceVendor == 0x07d1
		&& usb_conv_info->deviceProduct == 0x3b11) {
		dissect_topdog(tvb, pinfo, tree, data);
		return TRUE;
	}

	if (tvb_reported_length(tvb) < 4)
		return FALSE;

	if (!tvb_memeql(tvb, 0, mcbw, 4)
		|| !tvb_memeql(tvb, 0, mcsw, 4)
		|| !tvb_memeql(tvb, 0, mtxd, 4)
		|| !tvb_memeql(tvb, 0, mrxd, 4)) {
		dissect_topdog(tvb, pinfo, tree, data);
		return TRUE;
	}

	return FALSE;
}

void plugin_register(void)
{
	proto_topdog = proto_register_protocol("Marvell TopDog 88W8362", "TopDog", "topdog");
	proto_register_field_array(proto_topdog, hf, array_length(hf));
	proto_register_subtree_array(ett_list, array_length(ett_list));
	printf("wireshark-topdog-dissector: Reached plugin_register.\n");
}

void plugin_reg_handoff(void)
{
	heur_dissector_add("usb.bulk", dissect_topdog_bulk_heur, "Marvell TopDog 88W8362 USB bulk endpoint", "topdog_usb_bulk", proto_topdog, HEURISTIC_ENABLE);
	/* TODO: Is there a way to tell Wireshark that the 802.11 header is
	** *always* the 4-address format and *never* has the QoS Control field?
	** Maybe we need to produce a patch for packet-ieee802.11.c. */
	wlan_handle = find_dissector("wlan_noqos");
	printf("wireshark-topdog-dissector: Reached plugin_reg_handoff.\n");
}
