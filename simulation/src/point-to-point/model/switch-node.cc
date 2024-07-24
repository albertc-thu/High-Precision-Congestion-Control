#include "ns3/ipv4.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include "ns3/pause-header.h"
#include "ns3/flow-id-tag.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "switch-node.h"
#include "qbb-net-device.h"
#include "ppp-header.h"
#include "ns3/int-header.h"
#include <cmath>
#include <bitset>
using namespace std;

namespace ns3 {

void SwitchNode::SetSwitchId(uint32_t id){
	switch_id = id;
}

TypeId SwitchNode::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SwitchNode")
    .SetParent<Node> ()
    .AddConstructor<SwitchNode> ()
	.AddAttribute("EcnEnabled",
			"Enable ECN marking.",
			BooleanValue(false),
			MakeBooleanAccessor(&SwitchNode::m_ecnEnabled),
			MakeBooleanChecker())
	.AddAttribute("CcMode",
			"CC mode.",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ccMode),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("AckHighPrio",
			"Set high priority for ACK/NACK or not",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ackHighPrio),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("MaxRtt",
			"Max Rtt of the network",
			UintegerValue(9000),
			MakeUintegerAccessor(&SwitchNode::m_maxRtt),
			MakeUintegerChecker<uint32_t>())
  ;
  return tid;
}

SwitchNode::SwitchNode(){
	m_ecmpSeed = m_id;
	m_node_type = 1;
	m_mmu = CreateObject<SwitchMmu>();
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < pCnt; j++)
			for (uint32_t k = 0; k < qCnt; k++)
				m_bytes[i][j][k] = 0;
	for(uint32_t i = 0; i < pCnt; i++){
		output_q_bytes[i] = 0;
	}
	for (uint32_t i = 0; i < pCnt; i++)
		m_txBytes[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_lastPktSize[i] = m_lastPktTs[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_u[i] = 0;
}

int SwitchNode::GetOutDev(Ptr<const Packet> p, CustomHeader &ch){
	// look up entries
	auto entry = m_rtTable.find(ch.dip);

	// no matching entry
	if (entry == m_rtTable.end())
		return -1;

	// entry found
	auto &nexthops = entry->second;

	// pick one next hop based on hash
	union {
		uint8_t u8[4+4+2+2];
		uint32_t u32[3];
	} buf;
	buf.u32[0] = ch.sip;
	buf.u32[1] = ch.dip;
	if (ch.l3Prot == 0x6)
		buf.u32[2] = ch.tcp.sport | ((uint32_t)ch.tcp.dport << 16);
	else if (ch.l3Prot == 0x11)
		buf.u32[2] = ch.udp.sport | ((uint32_t)ch.udp.dport << 16);
	else if (ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)
		buf.u32[2] = ch.ack.sport | ((uint32_t)ch.ack.dport << 16);

	uint32_t idx = EcmpHash(buf.u8, 12, m_ecmpSeed) % nexthops.size();
	return nexthops[idx];
}

int SwitchNode::GetOutDevVir(Ptr<const Packet> p, CustomHeader &ch, uint32_t virtual_dip){
	// look up entries
	auto entry = m_rtTable.find(virtual_dip);

	// no matching entry
	if (entry == m_rtTable.end())
		return -1;

	// entry found
	auto &nexthops = entry->second;

	// pick one next hop based on hash
	union {
		uint8_t u8[4+4+2+2];
		uint32_t u32[3];
	} buf;
	buf.u32[0] = ch.sip;
	buf.u32[1] = virtual_dip;
	if (ch.l3Prot == 0x6)
		buf.u32[2] = ch.tcp.sport | ((uint32_t)ch.tcp.dport << 16);
	else if (ch.l3Prot == 0x11)
		buf.u32[2] = ch.udp.sport | ((uint32_t)ch.udp.dport << 16);
	else if (ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)
		buf.u32[2] = ch.ack.sport | ((uint32_t)ch.ack.dport << 16);

	uint32_t idx = EcmpHash(buf.u8, 12, m_ecmpSeed) % nexthops.size();
	return nexthops[idx];
}

int GetNextOutDev(Ptr<const Packet>, CustomHeader &ch) {
	
}


void SwitchNode::CheckAndSendPfc(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldPause(inDev, qIndex)){
		device->SendPfc(qIndex, 0);
		m_mmu->SetPause(inDev, qIndex);
	}
}
void SwitchNode::CheckAndSendResume(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldResume(inDev, qIndex)){
		device->SendPfc(qIndex, 1);
		m_mmu->SetResume(inDev, qIndex);
	}
}

int SwitchNode::GetHopCount(uint32_t sip, uint32_t dip){
	int src_id = (sip >> 8) & 0xffff;
	int dst_id = (dip >> 8) & 0xffff;
	int Rs = src_id / p_df;
	int Rd = dst_id / p_df;
	int Gs = src_id / (a_df * p_df);
	int Gd = dst_id / (a_df * p_df);
	int hop_count = 0;
	if (Rs == Rd){
		hop_count = 2;
	}
	else if (Gs == Gd){
		hop_count = 3;
	}
	else{
		// int inter_group_id = rand() % g_df;
		int Ra = find_router_id_in_this_group_to_that_group(Gs, Gd);
		int Rx = find_router_id_in_this_group_to_that_group(Gd, Gs);
		// int Rx = find_router_id_in_inter_group_to_dst_group(dst_group_id, src_group_id);
		if (Rs == Ra && Rd == Rx){
			hop_count = 3;
		}
		else if (Rs == Ra || Rd == Rx){
			hop_count = 4;
		}
		else{
			hop_count = 5;
		}
	}
	return hop_count;

}

bool SwitchNode::enable_VLB(Ptr<const Packet>p, CustomHeader &ch, uint32_t dip, uint32_t v_dip){
	// 这里需要模拟一个virtual channel
	// 随机选一个中间group, 本group内经过的ToR也确定下来: Ra
	// 然后去测q_vc， 也就是Rs前往Ra的队列中去往Gi的包的数量
	// int idx_direct = GetOutDev(p, ch);
	// int idx_indirect = GetOutDevVir(p, ch, v_dip);
	// int Hm = GetHopCount(ch.sip, dip) - 1;
	// int Hnm = GetHopCount(ch.sip, v_dip) - 2 + GetHopCount(v_dip, dip) - 1;
	// if (idx_direct != idx_indirect){
	// 	int qm = output_q_bytes[idx_direct];
	// 	int qnm = output_q_bytes[idx_indirect];
	// 	if(qm * Hm <= qnm * Hnm){
	// 		return false;
	// 	}
	// 	else{
	// 		return true;
	// 	}
	// }
	// else{
	// 	// int 
	// 	// int qvm = 

	// }
	return true;
}

bool SwitchNode:: is_same_group(uint32_t sip, uint32_t dip){
	uint32_t src_id = (sip >> 8) & 0xffff;
	uint32_t dst_id = (dip >> 8) & 0xffff;
	if (src_id / (a_df * p_df) == dst_id / (a_df * p_df)){
		return true;
	}
	return false;
}
int SwitchNode::find_router_id_in_this_group_to_that_group(int src_group_id, int inter_group_id){
	int idx = 0;
	int dis = (src_group_id - inter_group_id + g_df) % g_df;
	idx = src_group_id * a_df + (dis - 1) / h_df;
	return idx;
}
// int SwitchNode::find_router_id_in_inter_group_to_dst_group(int dst_group_id, int inter_group_id){
// 	int idx = 0;
// 	int dis = (inter_group_id - dst_group_id + g_df) % g_df;
// 	idx = inter_group_id * a_df + (dis - 1) / h_df;
// 	return idx;
// }
// int SwitchNode::VLB(Ptr<const Packet> p, CustomHeader &ch, int inter_group_id){
	
// 	// int virtual_dip = (inter_group_id * a_df * p) + (rand() % (a_df * p));
	
// 	// auto entry = m_rtTable.find(ch.dip);

// 	return 0;
// }

void SwitchNode::SendToDev(Ptr<Packet>p, CustomHeader &ch){
	// if (ch.is_indirect) std::cout << "1" << std::endl;
	int src_group_id = ((ch.sip >> 8) & 0xffff) / (a_df * p_df);
	int dst_group_id = ((ch.dip >> 8) & 0xffff) / (a_df * p_df);
	int inter_group_id = rand() % g_df;
	inter_group_id = 4;

	int Rs = ((ch.sip >> 8) & 0xffff) / p_df;
	int Ra = find_router_id_in_this_group_to_that_group(src_group_id, inter_group_id);
	int Rx = find_router_id_in_this_group_to_that_group(inter_group_id, dst_group_id);
	// uint32_t virtual_dip = 0x0b000001 + (((Rx * p_df) / 256) * 0x00010000) + (((Rx * p_df) % 256) * 0x00000100);
	
	uint32_t credit = 1;
	uint32_t v_dip = Rx * p_df;
	uint32_t v_dip_ipv4 = 0x0b000001 + (((v_dip) / 256) * 0x00010000) + (((v_dip) % 256) * 0x00000100);
	
	// v_dip = 0x0b000001 + (((v_dip) / 256) * 0x00010000) + (((v_dip) % 256) * 0x00000100);
	int idx = 0;
	int actual_dip = 0;
	// cout << "ch.l3Prot: " << ch.l3Prot << endl;
	// cout << p->GetTypeId() << endl;

	// std::cout << "🐶 " << std::endl;
	VLBTag v;
	bool first_time_to_switch = !(p->PeekPacketTag(v));
	// if(first_time_to_switch == true){
	// 	// this is a packet from NIC, add tag
	// 	uint32_t tag_to_enc = (credit << 16) | v_dip;
	// 	p->AddPacketTag(VLBTag(tag_to_enc));
	// }
	
	if (ch.l3Prot == 17){
		cout << "\n🐔now in switch: " << switch_id << endl;
		// cout << "header type: " << ch.headerType << endl;
		
		// cout << "ch.indirect_credit: " << ch.indirect_credit << endl;
		// cout << "indirect_credit: " << ch.indirect_credit << endl;
		// cout << "inter_group_id: " << inter_group_id << endl;
		// cout << "🐔now in switch: " << switch_id << ", ch.l3Prot: " << ch.l3Prot << endl;

		if(first_time_to_switch == true){
			// 决定是否要VLB
			if(inter_group_id == src_group_id || inter_group_id == dst_group_id){
				// ch.indirect_credit = 0;
				// TODO 将credit置为0
				credit = 0;
				idx = GetOutDev(p, ch); // MIN
				actual_dip = (ch.dip >> 8) & 0xffff;
				cout << "👼send directly ";
			}
			else if(!enable_VLB(p, ch, ch.dip, v_dip_ipv4)){
				credit = 0;
				idx = GetOutDev(p, ch); // MIN
				actual_dip = (ch.dip >> 8) & 0xffff;
				cout << "👼send directly ";
			}
			else{
				// 转发，将vlb tag置为1或0，按照虚拟地址发
				
				idx = GetOutDevVir(p, ch, v_dip_ipv4);
				actual_dip = v_dip;
				if (Rs == Ra){
					credit = 0;
				}
				else{
					credit = 1;
				}
				cout << "👹send indirectly ";
			}
			cout << ", idx: " << idx << endl;
			uint32_t tag_to_enc = (credit << 16) | v_dip;
			// cout << "credit: " << credit << endl;
			p->AddPacketTag(VLBTag(tag_to_enc));
		}
		else{
			// 解析VLBTag
			uint32_t tag = v.GetVLB();
			// cout << "tag: " << hex << (tag) << endl;
			uint32_t resolved_credit = (tag >> 16) & 0xffff;
			// cout << "resolved_credit: " << hex << resolved_credit << endl;
			uint32_t resolved_v_dip = tag & 0xffff;
			uint32_t resolved_v_dip_ipv4 = 0x0b000001 + (((resolved_v_dip) / 256) * 0x00010000) + (((resolved_v_dip) % 256) * 0x00000100);
			// resolved_v_dip = 0x0b000001 + (((resolved_v_dip) / 256) * 0x00010000) + (((resolved_v_dip) % 256) * 0x00000100);
			if (int(resolved_credit) != 0) { // credit为1，位于Ra，按照虚拟地址发，再将credit置为1
				idx = GetOutDevVir(p, ch, resolved_v_dip_ipv4);
				actual_dip = resolved_v_dip;
				resolved_credit = 0;
				// v.SetVLB(0);
				// 删除这个tag，重新添加
				p->RemovePacketTag(v);
				uint32_t tag_to_enc = (resolved_credit << 16) | resolved_v_dip;
				p->AddPacketTag(VLBTag(tag_to_enc));
				cout << "👹send indirectly, idx: " << idx << endl;
			}
			else { // credit 为0，MIN
				idx = GetOutDev(p, ch);
				actual_dip = (ch.dip >> 8) & 0xffff;
				cout << "👼send directly, idx: " << idx << endl;
			}
		}


		// if(inter_group_id == src_group_id || inter_group_id == dst_group_id || ch.indirect_credit == 0 || !enable_VLB()){
		// 	ch.indirect_credit = 0;
		// 	idx = GetOutDev(p, ch); // MIN
		// }
		// else if(ch.indirect_credit == 1){
		// 	idx = GetOutDevVir(p, ch);
		// 	ch.indirect_credit = 0;
		// }
		// else{
		// 	idx = GetOutDevVir(p, ch);
		// 	if (Rs == Ra){
		// 		ch.indirect_credit = 0;
		// 	}
		// 	else{
		// 		ch.indirect_credit = 1;
		// 	}
		// 	// cout << "Ra: " << Ra << " Rx: " << Rx << " Rs: " << Rs << endl;
		// 	// cout << endl;
		// }
	}
	else{
		idx = GetOutDev(p, ch);
		actual_dip = (ch.dip >> 8) & 0xffff;
	}
	// idx = GetOutDev(p, ch);
	
	

	if (idx >= 0){
		NS_ASSERT_MSG(m_devices[idx]->IsLinkUp(), "The routing table look up should return link that is up");

		// determine the qIndex
		uint32_t qIndex;
		if (ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC))){  //QCN or PFC or NACK, go highest priority
			qIndex = 0;
		}else{
			qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
		}
		// cout << "ch.udp.pg: " << ch.udp.pg << endl;

		// admission control
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();
		// cout << "🐢flow id: "	<< inDev << endl;
		if (qIndex != 0){ //not highest priority
			if (m_mmu->CheckIngressAdmission(inDev, qIndex, p->GetSize()) && m_mmu->CheckEgressAdmission(idx, qIndex, p->GetSize())){			// Admission control
				m_mmu->UpdateIngressAdmission(inDev, qIndex, p->GetSize());
				m_mmu->UpdateEgressAdmission(idx, qIndex, p->GetSize());
			}else{
				return; // Drop
			}
			CheckAndSendPfc(inDev, qIndex);
		}
		m_bytes[inDev][idx][qIndex] += p->GetSize();
		output_q_bytes[idx] += p->GetSize();
		// if (idx > p_df){
		// 	int next_idx = 
		// 	output_vq_bytes[idx][] += p->GetSize();
		// }
		
		m_devices[idx]->SwitchSend(qIndex, p, ch);
	}else
		return; // Drop
}

uint32_t SwitchNode::EcmpHash(const uint8_t* key, size_t len, uint32_t seed) {
  uint32_t h = seed;
  if (len > 3) {
    const uint32_t* key_x4 = (const uint32_t*) key;
    size_t i = len >> 2;
    do {
      uint32_t k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h += (h << 2) + 0xe6546b64;
    } while (--i);
    key = (const uint8_t*) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32_t k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

void SwitchNode::SetEcmpSeed(uint32_t seed){
	m_ecmpSeed = seed;
}

void SwitchNode::AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx){
	uint32_t dip = dstAddr.Get();
	m_rtTable[dip].push_back(intf_idx);
}

void SwitchNode::ClearTable(){
	m_rtTable.clear();
}

// This function can only be called in switch mode
bool SwitchNode::SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch){
	SendToDev(packet, ch);
	return true;
}

void SwitchNode::SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p){
	FlowIdTag t;
	p->PeekPacketTag(t);
	if (qIndex != 0){
		uint32_t inDev = t.GetFlowId();
		m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p->GetSize());
		m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex, p->GetSize());
		m_bytes[inDev][ifIndex][qIndex] -= p->GetSize();
		output_q_bytes[ifIndex] -= p->GetSize();
		if (m_ecnEnabled){
			bool egressCongested = m_mmu->ShouldSendCN(ifIndex, qIndex);
			if (egressCongested){
				PppHeader ppp;
				Ipv4Header h;
				p->RemoveHeader(ppp);
				p->RemoveHeader(h);
				h.SetEcn((Ipv4Header::EcnType)0x03);
				p->AddHeader(h);
				p->AddHeader(ppp);
			}
		}
		//CheckAndSendPfc(inDev, qIndex);
		CheckAndSendResume(inDev, qIndex);
	}
	if (1){
		uint8_t* buf = p->GetBuffer();
		if (buf[PppHeader::GetStaticSize() + 9] == 0x11){ // udp packet
			IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
			Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[ifIndex]);
			if (m_ccMode == 3){ // HPCC
				ih->PushHop(Simulator::Now().GetTimeStep(), m_txBytes[ifIndex], dev->GetQueue()->GetNBytesTotal(), dev->GetDataRate().GetBitRate());
			}else if (m_ccMode == 10){ // HPCC-PINT
				uint64_t t = Simulator::Now().GetTimeStep();
				uint64_t dt = t - m_lastPktTs[ifIndex];
				if (dt > m_maxRtt)
					dt = m_maxRtt;
				uint64_t B = dev->GetDataRate().GetBitRate() / 8; //Bps
				uint64_t qlen = dev->GetQueue()->GetNBytesTotal();
				double newU;

				/**************************
				 * approximate calc
				 *************************/
				int b = 20, m = 16, l = 20; // see log2apprx's paremeters
				int sft = logres_shift(b,l);
				double fct = 1<<sft; // (multiplication factor corresponding to sft)
				double log_T = log2(m_maxRtt)*fct; // log2(T)*fct
				double log_B = log2(B)*fct; // log2(B)*fct
				double log_1e9 = log2(1e9)*fct; // log2(1e9)*fct
				double qterm = 0;
				double byteTerm = 0;
				double uTerm = 0;
				if ((qlen >> 8) > 0){
					int log_dt = log2apprx(dt, b, m, l); // ~log2(dt)*fct
					int log_qlen = log2apprx(qlen >> 8, b, m, l); // ~log2(qlen / 256)*fct
					qterm = pow(2, (
								log_dt + log_qlen + log_1e9 - log_B - 2*log_T
								)/fct
							) * 256;
					// 2^((log2(dt)*fct+log2(qlen/256)*fct+log2(1e9)*fct-log2(B)*fct-2*log2(T)*fct)/fct)*256 ~= dt*qlen*1e9/(B*T^2)
				}
				if (m_lastPktSize[ifIndex] > 0){
					int byte = m_lastPktSize[ifIndex];
					int log_byte = log2apprx(byte, b, m, l);
					byteTerm = pow(2, (
								log_byte + log_1e9 - log_B - log_T
								)/fct
							);
					// 2^((log2(byte)*fct+log2(1e9)*fct-log2(B)*fct-log2(T)*fct)/fct) ~= byte*1e9 / (B*T)
				}
				if (m_maxRtt > dt && m_u[ifIndex] > 0){
					int log_T_dt = log2apprx(m_maxRtt - dt, b, m, l); // ~log2(T-dt)*fct
					int log_u = log2apprx(int(round(m_u[ifIndex] * 8192)), b, m, l); // ~log2(u*512)*fct
					uTerm = pow(2, (
								log_T_dt + log_u - log_T
								)/fct
							) / 8192;
					// 2^((log2(T-dt)*fct+log2(u*512)*fct-log2(T)*fct)/fct)/512 = (T-dt)*u/T
				}
				newU = qterm+byteTerm+uTerm;

				#if 0
				/**************************
				 * accurate calc
				 *************************/
				double weight_ewma = double(dt) / m_maxRtt;
				double u;
				if (m_lastPktSize[ifIndex] == 0)
					u = 0;
				else{
					double txRate = m_lastPktSize[ifIndex] / double(dt); // B/ns
					u = (qlen / m_maxRtt + txRate) * 1e9 / B;
				}
				newU = m_u[ifIndex] * (1 - weight_ewma) + u * weight_ewma;
				printf(" %lf\n", newU);
				#endif

				/************************
				 * update PINT header
				 ***********************/
				uint16_t power = Pint::encode_u(newU);
				if (power > ih->GetPower())
					ih->SetPower(power);

				m_u[ifIndex] = newU;
			}
		}
	}
	m_txBytes[ifIndex] += p->GetSize();
	m_lastPktSize[ifIndex] = p->GetSize();
	m_lastPktTs[ifIndex] = Simulator::Now().GetTimeStep();
}

int SwitchNode::logres_shift(int b, int l){
	static int data[] = {0,0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5};
	return l - data[b];
}

int SwitchNode::log2apprx(int x, int b, int m, int l){
	int x0 = x;
	int msb = int(log2(x)) + 1;
	if (msb > m){
		x = (x >> (msb - m) << (msb - m));
		#if 0
		x += + (1 << (msb - m - 1));
		#else
		int mask = (1 << (msb-m)) - 1;
		if ((x0 & mask) > (rand() & mask))
			x += 1<<(msb-m);
		#endif
	}
	return int(log2(x) * (1<<logres_shift(b, l)));
}

} /* namespace ns3 */
