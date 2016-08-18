package org.uCracker.util;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;

import net.sourceforge.jpcap.capture.CaptureDeviceLookupException;
import net.sourceforge.jpcap.capture.CaptureDeviceNotFoundException;
import net.sourceforge.jpcap.capture.CaptureDeviceOpenException;
import net.sourceforge.jpcap.capture.CapturePacketException;
import net.sourceforge.jpcap.capture.InvalidFilterException;
import net.sourceforge.jpcap.capture.PacketCapture;
import net.sourceforge.jpcap.capture.PacketListener;

public class Sniffer {

	private static final Logger LOG = Logger.getLogger(Sniffer.class);

	private static final int INFINITE = -1;
	private static final int PACKET_COUNT = INFINITE;

	private static String filter = "ip and tcp";

	PacketCapture pcap;
	List<PacketListener> packetListeners;

	public Sniffer(ArgsPresentator argsPresentator) {
		pcap = new PacketCapture();
		packetListeners = new LinkedList<PacketListener>();
	}

	public void addHostFilters(List<String> hosts) {
		StringBuffer sb = new StringBuffer();
		sb.append(filter);
		sb.append(" and ( ");
		int i = 0;
		for (String host : hosts) {
			sb.append("host ");
			sb.append(host);
			if (i != hosts.size() - 1) {
				sb.append(" or ");
			}
			i++;
		}
		sb.append(" )");
		filter = sb.toString();
	}

	public void addPacketListener(PacketListener packetListener) {
		pcap.addPacketListener(packetListener);
	}

	/***
	 * Sniffs the given interface
	 * @param inet
	 * @throws CaptureDeviceNotFoundException 
	 * @throws CaptureDeviceOpenException 
	 * @throws InvalidFilterException 
	 * @throws CapturePacketException 
	 * @throws CaptureDeviceLookupException 
	 * @throws UnsupportedOperationException 
	 * @throws IllegalArgumentException 
	 * @throws Exception
	 */
	public void sniff(String inet) throws CaptureDeviceNotFoundException, CaptureDeviceOpenException, InvalidFilterException, CapturePacketException, IllegalArgumentException, UnsupportedOperationException, CaptureDeviceLookupException {
		if (inet == null) {
			inet = pcap.findDevice();
		}
		//http://stackoverflow.com/questions/27353784/getting-interface-name-address-from-or-mapping-networkinterface-to-jpcap-devic
		//http://stackoverflow.com/questions/62289/read-write-to-windows-registry-using-java/6163701#6163701
		//http://stackoverflow.com/questions/9483379/jpcap-dll-on-a-64-bit-system
		List<NetworkDeviceInfo> infos = new ArrayList<NetworkDeviceInfo>();

		// Info can be queried from jpcap device string.
		for (String jpcapDevice : PacketCapture.lookupDevices())
			infos.add(new NetworkDeviceInfo(jpcapDevice));

		// Info can be displayed.
		for (NetworkDeviceInfo info : infos) {
			System.out.println(info.getJpcapDeviceName() + ":");
			System.out.println("  Description:   " + info.getDriverName());
			System.out.println("  Vendor:        " + info.getDriverVendor());
			System.out.println("  Address:       " + info.getInterfaceAddress());
			System.out.println("  Subnet Mask:   " + info.getInterfaceSubnetMask());
			System.out.println("  jpcap Display: " + info.getJpcapDisplayName());
			System.out.println("  GUID:          " + info.getGuid());
		}

		// Device names from NetworkDeviceInfo can be passed directly to jpcap:
		NetworkDeviceInfo selected = infos.get(2);
		// Initialize jpcap
		LOG.trace("Using device '" + selected.getJpcapDeviceName() + "'");
		pcap.open(selected.getJpcapDeviceName(), 4000, true, 5000);

		pcap.setFilter(filter, true);
		for (PacketListener packetListener : packetListeners) {
			pcap.addPacketListener(packetListener);
		}
		LOG.trace("Capturing packets...");
		pcap.capture(PACKET_COUNT);
	}

}
