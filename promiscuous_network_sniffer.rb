#!/usr/bin/env ruby

require 'packetfu'
puts "Promiscuous network sniffer for PacketFu #{PacketFu.version}"
include PacketFu

#default iface is eth0
iface = ARGV[0] || PacketFu::Utils.default_int

def sniff(iface)
  cap = Capture.new(:iface => iface, :promisc => true, :start => true)
  #|p| is the raw packet
  cap.stream.each do |p|
    #parse because we want to filter tcp/udp packets
    pkt = Packet.parse p
    if pkt.is_ip?
      #print information that we want to stdout
      packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
      #%-15s is a negative padding for strings, adds 15 whitespace to the right.
      #%-4d  is a negative padding for decimals, adds 4 whitespace to the right.
      puts "%-15s -> %-15s %-4d %s" % packet_info
    end
  end
end

sniff(iface
