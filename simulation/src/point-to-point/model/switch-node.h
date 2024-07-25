#ifndef SWITCH_NODE_H
#define SWITCH_NODE_H

#include <unordered_map>
#include <ns3/node.h>
#include "qbb-net-device.h"
#include "switch-mmu.h"
#include "pint.h"
#include "ns3/vlb-tag.h"

namespace ns3 {

class Packet;

class SwitchNode : public Node{
	static const uint32_t pCnt = 257;	// Number of ports used
	static const uint32_t qCnt = 8;	// Number of queues/priorities used
	
	uint32_t switch_id;
	uint32_t m_ecmpSeed;
	std::unordered_map<uint32_t, std::vector<int> > m_rtTable; // map from ip address (u32) to possible ECMP port (index of dev)

	// monitor of PFC
	uint32_t m_bytes[pCnt][pCnt][qCnt]; // m_bytes[inDev][outDev][qidx] is the bytes from inDev enqueued for outDev at qidx
	uint32_t output_q_bytes[pCnt]; // output queue bytes
	uint32_t output_vq_bytes[pCnt][2]; // output virtual queue bytes, 一个作为minimal queue，一个作为non-minimal queue

	uint64_t m_txBytes[pCnt]; // counter of tx bytes

	uint32_t m_lastPktSize[pCnt];
	uint64_t m_lastPktTs[pCnt]; // ns
	double m_u[pCnt];

protected:
	bool m_ecnEnabled;
	uint32_t m_ccMode;
	uint64_t m_maxRtt;

	uint32_t m_ackHighPrio; // set high priority for ACK/NACK

private:
	int GetOutDev(Ptr<const Packet>, CustomHeader &ch);
	int GetOutDevVir(Ptr<const Packet>, CustomHeader &ch, uint32_t virtual_dip);
	int GetNextOutDev(Ptr<const Packet>, CustomHeader &ch);
	int GetNextOutDevVir(Ptr<const Packet>, CustomHeader &ch, uint32_t virtual_dip);
	int VLB(Ptr<const Packet> p, CustomHeader &ch, int inter_group_id);
	bool is_same_group(uint32_t sip, uint32_t dip); // 本函数用于判断两个ip是否在同一个group中
	int GetHopCount(uint32_t sip, uint32_t dip); // 本函数用于计算两个ip之间的跳数
	bool enable_VLB(Ptr<const Packet>, CustomHeader &ch, uint32_t dip, uint32_t v_dip);
	int find_router_id_in_this_group_to_that_group(int src_group_id, int dst_group_id);
	// int find_router_id_in_inter_group_to_dst_group(int dst_group_id, int inter_group_id);
	void SendToDev(Ptr<Packet>p, CustomHeader &ch);
	static uint32_t EcmpHash(const uint8_t* key, size_t len, uint32_t seed);
	void CheckAndSendPfc(uint32_t inDev, uint32_t qIndex);
	void CheckAndSendResume(uint32_t inDev, uint32_t qIndex);
public:
	Ptr<SwitchMmu> m_mmu;
	static const uint32_t a_df = 4; // df means dragonfly
	static const uint32_t p_df = 2; // df means dragonfly
	static const uint32_t h_df = 2;	// df means dragonfly
	static const uint32_t g_df = 9; // df means dragonfly

	void SetSwitchId(uint32_t id);
	static TypeId GetTypeId (void);
	SwitchNode();
	void SetEcmpSeed(uint32_t seed);
	void AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx);
	void ClearTable();
	bool SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch);
	void SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p);

	// for approximate calc in PINT
	int logres_shift(int b, int l);
	int log2apprx(int x, int b, int m, int l); // given x of at most b bits, use most significant m bits of x, calc the result in l bits
};

} /* namespace ns3 */

#endif /* SWITCH_NODE_H */
