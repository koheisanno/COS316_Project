// ---------------------------------------------------------------------
// Simulates an iptable implementation with in-memory datastructures
// ---------------------------------------------------------------------

package main

import (
	"fmt"
	"net"
)

// TableType defines types of tables within an iptable.
type TableType string

// Defining Table Tupes
const (
    // main table where firewall rules are applied
    Filter TableType = "filter"
    // used for network address translation (ex:- port forwarding)
    Nat    TableType = "nat"
	// used to adjust the headers of an IP packet. For example: altering the TTL
    Mangle TableType = "mangle"
)

// A table represents an iptables table.
type Table struct {
    Name   TableType
    // each table can have multiple chains
    Chains []Chain
}

// ChainType defines types of iptables chains.
type ChainType string

// Predefined chain types.
// We are only considering these 3. But note that there are others such as,
// prerouting, postrouting chains
const (
    Input   ChainType = "INPUT"
    Forward ChainType = "FORWARD"
    Output  ChainType = "OUTPUT"
)

// Chain represents an iptables chain.
type Chain struct {
    Name  ChainType
    Rules []Rule
}

// Rule represents an iptables rule.
// nil Src or Dst means that the rule accepts any src and/or dst IP
type Rule struct { 
    Src      *net.IPNet // IPNet is a struct with IP address and subnet mask(allows us to partition network and host)
    Dst      *net.IPNet 
    Protocol string
    Action   Target
}

// TargetType defines types of iptables targets.
type TargetType string

// Target types.
const (
    Accept TargetType = "ACCEPT"
    Drop   TargetType = "DROP"
    Reject TargetType = "REJECT"
)

// Target represents an iptables target.
type Target struct {
    Type TargetType
}

// Packet represents a network packet.
type Packet struct {
    Src      net.IP
    Dst      net.IP
    Protocol string
}

// ProcessPacket processes a packet through the table and returns an action.
func (t Table) ProcessPacketThroughTable(packet Packet) TargetType {
    for _, chain := range t.Chains {
        action := chain.ProcessPacketThroughChain(packet)
        if action != "" {
            return action
        }
    }
    return Drop // Default action is to drop the packet if no rules match
}

// ProcessPacket processes a packet through the chain.
func (c Chain) ProcessPacketThroughChain(packet Packet) TargetType {
    for _, rule := range c.Rules {
        if rule.Matches(packet) {
            return rule.Action.Type
        }
    }
    return TargetType(Drop) // No action specified if no rules match
}

// Checks if the input packet matches the rule.
func (r Rule) Matches(packet Packet) bool {
    // if Src or Dst is not nil, it needs to contain the packet Src/Dst for it to match

    if r.Src != nil && !r.Src.Contains(packet.Src) {
        return false
    }
    if r.Dst != nil && !r.Dst.Contains(packet.Dst) {
        return false
    }
    // protocols need to be empty OR match
    if r.Protocol != "" && r.Protocol != packet.Protocol {
        return false
    }
    return true
}

func main() {

    // Case 1: Creating a Filter Table with one Input Chain with a rule that accepts all tcp packets.
    table := Table{
        Name: Filter,
        Chains: []Chain{
            {
                Name: Input,
                Rules: []Rule{
                    {
                        Src:      nil, // nil means any source
                        Dst:      nil, // nil means any destination
                        Protocol: "tcp",
                        Action:   Target{Type: Accept},
                    },
                },
            },
        },
    }

    // Simulating packet processing.
    packet := Packet{
        Src:      net.ParseIP("192.168.1.100"),
        Dst:      net.ParseIP("192.168.1.200"),
        Protocol: "tcp",
    }

    action1 := table.ProcessPacketThroughTable(packet)
    fmt.Printf("Packet action 1 is: %s\n", action1)

    // Case 2: Appending an input chain that only accepts a specific IP address


    srcIpAddress := net.IP{192, 168, 2, 100}
    srcSubnetMask := net.CIDRMask(24, 32) // Equivalent to "255.255.255.0"

    // net.IPNet structure
    srcIpNet := net.IPNet{
        IP:   srcIpAddress,
        Mask: srcSubnetMask,
    }

    dstIpAddress := net.IP{192, 178, 2, 200}
    dstSubnetMask := net.CIDRMask(24, 32) // Equivalent to "255.255.255.0"

    // net.IPNet structure
    dstIpNet := net.IPNet{
        IP:   dstIpAddress,
        Mask: dstSubnetMask,
    }

    table.Chains = append([]Chain{
        {
            Name: Input,
            Rules: []Rule{
                {
                    Src:      &srcIpNet, // nil means any source
                    Dst:      &dstIpNet, // nil means any destination
                    Protocol: "tcp",
                    Action:   Target{Type: Accept},
                },
            },
        },
    }, table.Chains...)
    
    action2 := table.ProcessPacketThroughTable(packet)
    fmt.Printf("Packet action 1 is: %s\n", action2)
}
