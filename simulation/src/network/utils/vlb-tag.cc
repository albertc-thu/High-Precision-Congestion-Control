/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008 INRIA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */
#include "vlb-tag.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (VLBTag);

TypeId 
VLBTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::VLBTag")
    .SetParent<Tag> ()
    .AddConstructor<VLBTag> ()
  ;
  return tid;
}
TypeId 
VLBTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
uint32_t 
VLBTag::GetSerializedSize (void) const
{
  return 4;
}
void 
VLBTag::Serialize (TagBuffer buf) const
{
  buf.WriteU32 (m_vlb);
}
void 
VLBTag::Deserialize (TagBuffer buf)
{
  m_vlb = buf.ReadU32 ();
}
void 
VLBTag::Print (std::ostream &os) const
{
  os << "VLB=" << m_vlb;
}
VLBTag::VLBTag ()
  : Tag () 
{
}

VLBTag::VLBTag (uint32_t vlb)
  : Tag (),
    m_vlb (vlb)
{
}

void
VLBTag::SetVLB (uint32_t vlb)
{
  m_vlb = vlb;
}
uint32_t
VLBTag::GetVLB (void) const
{
  return m_vlb;
}

uint32_t 
VLBTag::AllocateVLB (void)
{
  static uint32_t nextVLB = 1;
  uint32_t vlb = nextVLB;
  nextVLB++;
  return vlb;
}

} // namespace ns3