from operator import attrgetter
from ryu.base import app_manager
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub

class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


	def __init__(self, *args, **kwargs):
	        super(SimpleSwitch13, self).__init__(*args, **kwargs)
	        self.datapaths = {}
		self.arp_table={}
		self.arp_table['10.0.0.1'] = '00:00:00:00:00:01'
		self.arp_table['10.0.0.2'] = '00:00:00:00:00:02'
		self.arp_table['10.0.0.3'] = '00:00:00:00:00:03'
	        self.monitor_thread = hub.spawn(self._monitor)

	@set_ev_cls(ofp_event.EventOFPStateChange,
	                [MAIN_DISPATCHER, DEAD_DISPATCHER])
	def switch_features_handler(self, ev):
	        datapath = ev.datapath
		ofproto = datapath.ofproto
	        parser = datapath.ofproto_parser
		match = parser.OFPMatch()
	        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
	        self.add_flow(datapath, 0, match, actions)
		if ev.state == MAIN_DISPATCHER:
	            if datapath.id not in self.datapaths:
	                self.logger.debug('register datapath: %016x', datapath.id)
	                self.datapaths[datapath.id] = datapath
	        elif ev.state == DEAD_DISPATCHER:
	            if datapath.id in self.datapaths:
	                self.logger.debug('unregister datapath: %016x', datapath.id)
	                del self.datapaths[datapath.id]
		dpid = datapath.id
		###### switch 1   ######
		if dpid == 1:
		
		## UDP forwarding ##
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 3)
		
###### switch 3   ######
		if dpid == 3:
		
			## UDP forwarding ##
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 2)
		
###### switch 4   ######
		if dpid == 4:
		
		## UDP forwarding ##
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 2)
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 1)
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 2)


###### switch 5   ######
		if dpid == 5:
		
		## UDP forwarding ##
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 2)
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
			self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 1)
	
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
	        msg = ev.msg
	        datapath = msg.datapath
	        ofproto = datapath.ofproto
	        parser = datapath.ofproto_parser
	        
	        in_port = msg.match['in_port']
	        pkt = packet.Packet(msg.data)
	        eth = pkt.get_protocol(ethernet.ethernet)
	        ethertype = eth.ethertype

		## IP ##
	        if ethertype == ether.ETH_TYPE_IP:
	            self.handle_ip(datapath, in_port, pkt)
	            return
        
		## ARP ## 
	        if ethertype == ether.ETH_TYPE_ARP:
	            self.handle_arp(datapath, in_port, pkt)
	            return

	def add_layer4_rules(self, datapath, ip_proto, ipv4_dst = None, priority = 1, fwd_port = None):
	        parser = datapath.ofproto_parser
	        actions = [parser.OFPActionOutput(fwd_port)]
	        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                ip_proto = ip_proto,
                                ipv4_dst = ipv4_dst)
	        self.add_flow(datapath, priority, match, actions)
  
	def add_flow(self, datapath, priority, match, actions):
	        ofproto = datapath.ofproto
	        parser = datapath.ofproto_parser
	
	        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
		                                             actions)]

	        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
	                                match=match, instructions=inst)
	        datapath.send_msg(mod)
	def handle_arp(self, datapath, in_port, pkt):
	        ofproto = datapath.ofproto
	        parser = datapath.ofproto_parser
	
        # parse out the ethernet and arp packet
	        eth_pkt = pkt.get_protocol(ethernet.ethernet)
	        arp_pkt = pkt.get_protocol(arp.arp)
	        # obtain the MAC of dst IP  
	        arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]
	
	        arp_reply= packet.Packet()
	        arp_reply.add_protocol(ethernet.ethernet(dst = eth_pkt.src,
	                                                 src = arp_resolv_mac,
	                                                 ethertype = ether.ETH_TYPE_ARP))
	        arp_reply.add_protocol(arp.arp(hwtype = 1,
	                                       proto = 0x0800, 
	                                       hlen = 6, 
	                                       plen = 4,
	                                       opcode=2,
	                                       src_mac=arp_resolv_mac,
	                                       src_ip=arp_pkt.dst_ip,
                	                       dst_mac=eth_pkt.src,
	                                       dst_ip=arp_pkt.src_ip))
		arp_reply.serialize()
        
        # send the Packet Out mst to back to the host who is initilaizing the ARP
		actions = [parser.OFPActionOutput(in_port)];
	        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, 
                                  ofproto.OFPP_CONTROLLER, actions,
                                  arp_reply.data)
        	datapath.send_msg(out)
	def handle_ip(self, datapath, in_port, pkt):
	        ofproto = datapath.ofproto
	        parser = datapath.ofproto_parser

	        ipv4_pkt = pkt.get_protocol(ipv4.ipv4) 
		udp_pkt = pkt.get_protocol(udp.udp)
		eth_pkt = pkt.get_protocol(ethernet.ethernet)
	# switch 1
		if (datapath.id == 1 and ipv4_pkt.proto == inet.IPPROTO_UDP):
					
			# send tcp flow from H1 To H2 on port 2				
			match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.1',
											ipv4_dst = '10.0.0.2',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions = [parser.OFPActionOutput(2)]
			self.add_flow(datapath, 65535, match, actions)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions,
										  msg.data)
			datapath.send_msg(out)
			# send udp from h1 to h3
			match1 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.1',
											ipv4_dst = '10.0.0.3',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions1 = [parser.OFPActionOutput(3)]
			self.add_flow(datapath, 65535, match1, actions1)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions1,
										  msg.data)
			datapath.send_msg(out)
				# Send udp flow from h2 to h1 on port 1
			match2 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.2',
											ipv4_dst = '10.0.0.1',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions2 = [parser.OFPActionOutput(1)]
			self.add_flow(datapath, 65535, match2, actions2)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions2,
										  msg.data)
			datapath.send_msg(out)
			
			# Send udp flow from h3 to h1 on port 1
			match3 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.3',
											ipv4_dst = '10.0.0.1',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions3 = [parser.OFPActionOutput(1)]
			self.add_flow(datapath, 65535, match3, actions3)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions3,
										  msg.data)
			datapath.send_msg(out)
		elif (datapath.id == 2):
			match = parser.OFPMAtch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.1',
											ipv4_dst = '10.0.0.3',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions=[]
			self.add_flow(datapath,65535, match, actions)
			out = parser.OFPPAcketOut(datapath,ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions,
										  msg.data)
			#switch 3
		elif (datapath.id == 3 and ipv4_pkt.proto == inet.IPPROTO_UDP):
				
								
			# send tcp flow from H1 To H2 on port 2				
			match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.1',
											ipv4_dst = '10.0.0.2',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions = [parser.OFPActionOutput(2)]
			self.add_flow(datapath, 65535, match, actions)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions,
										  msg.data)
			datapath.send_msg(out)
			# send udp from h1 to h3
			match1 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.1',
											ipv4_dst = '10.0.0.3',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions1 = [parser.OFPActionOutput(2)]
			self.add_flow(datapath, 65535, match1, actions1)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions1,
										  msg.data)
			datapath.send_msg(out)
				# Send udp flow from h2 to h1 on port 1
			match2 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.2',
											ipv4_dst = '10.0.0.1',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions2 = [parser.OFPActionOutput(1)]
			self.add_flow(datapath, 65535, match2, actions2)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions2,
										  msg.data)
			datapath.send_msg(out)
			
			# Send udp flow from h3 to h1 on port 1
			match3 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.3',
											ipv4_dst = '10.0.0.1',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions3 = [parser.OFPActionOutput(1)]
			self.add_flow(datapath, 65535, match3, actions3)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions3,
										  msg.data)
			datapath.send_msg(out)
			# switch 4
		elif (datapath.id == 4 and ipv4_pkt.proto == inet.IPPROTO_UDP):
				
				
				# send tcp from h2 to h1
			match1 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.2',
											ipv4_dst = '10.0.0.1',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
				# send on flow from even port number on port 2
			actions1 = [parser.OFPActionOutput(2)]
			self.add_flow(datapath, 65535, match1, actions1)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions1,
										  msg.data)
			datapath.send_msg(out)
				# send flows from h1 to h2 on port 1
			match2 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.1',
											ipv4_dst = '10.0.0.2',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions2 = [parser.OFPActionOutput(1)]
			self.add_flow(datapath, 65535, match2, actions2)
			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions2, msg.data)
			datapath.send_msg(out)	

			# send udp from h2 to h3
			match3 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.2',
											ipv4_dst = '10.0.0.3',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
				# send on flow from even port number on port 2
			actions3 = [parser.OFPActionOutput(2)]
			self.add_flow(datapath, 65535, match3, actions3)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions3,
										  msg.data)
			datapath.send_msg(out)
				# send flows from h3 to h2 on port 1
			match4 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.3',
											ipv4_dst = '10.0.0.2',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions4 = [parser.OFPActionOutput(1)]
			self.add_flow(datapath, 65535, match4, actions4)
			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions4, msg.data)
			datapath.send_msg(out)	
		# switch 5
		elif (datapath.id == 5 and ipv4_pkt.proto == inet.IPPROTO_UDP):
				
				
				# send tcp from h1 to h3
			match1 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.1',
											ipv4_dst = '10.0.0.3',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
				# send on flow from even port number on port 2
			actions1 = [parser.OFPActionOutput(1)]
			self.add_flow(datapath, 65535, match1, actions1)

			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions1,
										  msg.data)
			datapath.send_msg(out)
				# send flows from h3 to h1 on port 1
			match2 = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
											ipv4_src = '10.0.0.3',
											ipv4_dst = '10.0.0.1',
											udp_dst = udp_pkt.dst_port,
											udp_src = udp_pkt.src_port,
											ip_proto = inet.IPPROTO_UDP)
			actions2 = [parser.OFPActionOutput(2)]
			self.add_flow(datapath, 65535, match2, actions2)
			out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
										  ofproto.OFPP_CONTROLLER, actions2, msg.data)
			datapath.send_msg(out)	










	def _monitor(self):
	        while True:
	            for dp in self.datapaths.values():
	                self._request_stats(dp)
	            hub.sleep(10)

	def _request_stats(self, datapath):
	        self.logger.debug('send stats request: %016x', datapath.id)
	        ofproto = datapath.ofproto
	        parser = datapath.ofproto_parser

	        req = parser.OFPFlowStatsRequest(datapath)
	        datapath.send_msg(req)

	        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
	        datapath.send_msg(req)
	
	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def _flow_stats_reply_handler(self, ev):
	        body = ev.msg.body

	        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
	        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
	        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
	            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def _port_stats_reply_handler(self, ev):
		f1= open("s4rx.txt", "a+")
		f2= open("s1rx.txt", "a+")
		f3= open("s5rx.txt", "a+")	
		f4= open("s3tx.txt", "a+")
		
		
		body = ev.msg.body

	        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
	        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
		
		for stat in sorted(body, key=attrgetter('port_no')):
			self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
			if (ev.msg.datapath.id == 4 and stat.port_no == 2):
				f1.write("%f \r \n" %(stat.rx_bytes))
			elif (ev.msg.datapath.id == 1 and stat.port_no== 2):
				f2.write("%f \r \n" %(stat.rx_bytes))
			elif (ev.msg.datapath.id == 5 and stat.port_no== 2):
				f3.write("%f \r \n"%(stat.rx_bytes))
			elif (ev.msg.datapath.id == 3 and stat.port_no== 2):
				f4.write("%f \r \n"%(stat.tx_bytes))
		f1.close()
		f2.close()
		f3.close()
		f4.close()
