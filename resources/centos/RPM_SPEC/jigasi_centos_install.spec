Summary: JItsi GAteway to SIP : a server-side application that links allows regular SIP clients to join JitMeet conferences hosted by Jitsi Videobridge.
Name: jigasi_centos7.1
Version: 2.0.15
Release: 0
Source: jigasi_centos.tar.gz
License: GPL
Group: Development/Tools
%description
Managing media sessions between each of the participants and the videobridge
%prep
# jigasi centos install
rm -rf $RPM_BUILD_DIR/jigasi_centos
zcat $RPM_SOURCE_DIR/jigasi_centos.tar.gz | tar -xvf -
%build
%install
mkdir -p $RPM_BUILD_ROOT/etc/init.d
mkdir -p $RPM_BUILD_ROOT/etc/jitsi
mkdir -p $RPM_BUILD_ROOT/etc/jitsi/jigasi
mkdir -p $RPM_BUILD_ROOT/usr/share
mkdir -p $RPM_BUILD_ROOT/usr/share/jigasi
mkdir -p $RPM_BUILD_ROOT/usr/share/jigasi/lib
mkdir -p $RPM_BUILD_ROOT/usr/share/jigasi/lib/native
mkdir -p $RPM_BUILD_ROOT/usr/share/jigasi/lib/native/linux-64
#/etc/init.d
install -m 755 jigasi_centos/etc/init.d/jigasi $RPM_BUILD_ROOT/etc/init.d/
#/etc/jitsi/jigasi
install -m 755 jigasi_centos/etc/jitsi/jigasi/sip-communicator.properties.default $RPM_BUILD_ROOT/etc/jitsi/jigasi/
install -m 755 jigasi_centos/etc/jitsi/jigasi/config.default $RPM_BUILD_ROOT/etc/jitsi/jigasi/
#/usr/share/jigasi
install -m 755 jigasi_centos/usr/share/jigasi/jigasi.jar $RPM_BUILD_ROOT/usr/share/jigasi/
install -m 755 jigasi_centos/usr/share/jigasi/jigasi.sh $RPM_BUILD_ROOT/usr/share/jigasi/
#/usr/share/jigasi/lib
install -m 755 jigasi_centos/usr/share/jigasi/lib/agafua-syslog.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/bccontrib.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/bcpkix-jdk15on.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/bcprov-jdk15on.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/commons-codec.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/commons-lang3.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/commons-lang.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/commons-logging.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/concurrentlinkedhashmap-lru.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/core.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/dbus-java.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/debug.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/dnsjava.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/dom4j.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/fmj.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/guava.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/hexdump.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/httpclient.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/httpcore.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/httpmime.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/ice4j.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jain-sip-ri-ossonly.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/java-sdp-nist-bridge.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/javax.servlet-api.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
#install -m 755 jigasi_centos/usr/share/jigasi/lib/javax.servlet.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jcip-annotations.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
#install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-ajp.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-client.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
#install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-continuation.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-http.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-io.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-proxy.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-security.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-server.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-servlet.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-util.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-webapp.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jetty-xml.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jicoco.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-android-osgi.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-argdelegation.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-certificate.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-configuration.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-contactlist.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-credentialsstorage.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-desktoputil.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-dns.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-dnsservice.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-fileaccess.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-globaldisplaydetails.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-hid.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-lgpl-dependencies.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-muc.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-neomedia.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-netaddr.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-notification-service.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-packetlogging.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-protocol-jabber.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-protocol.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-protocol-media.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-protocol-sip.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-reconnect.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-resourcemanager.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-sysactivity.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-systray-service.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-ui-service.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-util.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jitsi-version.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jna.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jnsapi.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/json-simple.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/jzlib.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/laf-widget.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/libidn.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/libjitsi.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/libunix.so $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/log4j.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/orange-extensions.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/org.apache.felix.framework.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/org.apache.felix.main.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/org.osgi.core.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/sdes4j.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/sdp-api.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/sip-api-1.2.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/slf4j-api.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/slf4j-jdk14.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/smack.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/smackx.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/tinder.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/unix.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/weupnp.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/xml-apis.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/xmlpull.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/xpp3.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/zrtp4j-light.jar $RPM_BUILD_ROOT/usr/share/jigasi/lib/
install -m 755 jigasi_centos/usr/share/jigasi/lib/logging.properties $RPM_BUILD_ROOT/usr/share/jigasi/lib/
#/usr/share/jigasi/lib/native/linux-64
install -m 755 jigasi_centos/usr/share/jigasi/lib/native/linux-64/libhwaddressretriever.so $RPM_BUILD_ROOT/usr/share/jigasi/lib/native/linux-64/
%files
#/etc/init.d
/etc/init.d/jigasi
#/etc/jitsi/jigasi
/etc/jitsi/jigasi/sip-communicator.properties.default
/etc/jitsi/jigasi/config.default
#/usr/share/jigasi
/usr/share/jigasi/jigasi.jar
/usr/share/jigasi/jigasi.sh
#/usr/share/jigasi/lib
/usr/share/jigasi/lib/agafua-syslog.jar
/usr/share/jigasi/lib/bccontrib.jar
/usr/share/jigasi/lib/bcpkix-jdk15on.jar
/usr/share/jigasi/lib/bcprov-jdk15on.jar
/usr/share/jigasi/lib/commons-codec.jar
/usr/share/jigasi/lib/commons-lang3.jar
/usr/share/jigasi/lib/commons-lang.jar
/usr/share/jigasi/lib/commons-logging.jar
/usr/share/jigasi/lib/concurrentlinkedhashmap-lru.jar
/usr/share/jigasi/lib/core.jar
/usr/share/jigasi/lib/dbus-java.jar
/usr/share/jigasi/lib/debug.jar
/usr/share/jigasi/lib/dnsjava.jar
/usr/share/jigasi/lib/dom4j.jar
/usr/share/jigasi/lib/fmj.jar
/usr/share/jigasi/lib/guava.jar
/usr/share/jigasi/lib/hexdump.jar
/usr/share/jigasi/lib/httpclient.jar
/usr/share/jigasi/lib/httpcore.jar
/usr/share/jigasi/lib/httpmime.jar
/usr/share/jigasi/lib/ice4j.jar
/usr/share/jigasi/lib/jain-sip-ri-ossonly.jar
/usr/share/jigasi/lib/java-sdp-nist-bridge.jar
/usr/share/jigasi/lib/javax.servlet-api.jar
#/usr/share/jigasi/lib/javax.servlet.jar
/usr/share/jigasi/lib/jcip-annotations.jar
#/usr/share/jigasi/lib/jetty-ajp.jar
/usr/share/jigasi/lib/jetty-client.jar
#/usr/share/jigasi/lib/jetty-continuation.jar
/usr/share/jigasi/lib/jetty-http.jar
/usr/share/jigasi/lib/jetty-io.jar
/usr/share/jigasi/lib/jetty-proxy.jar
/usr/share/jigasi/lib/jetty-security.jar
/usr/share/jigasi/lib/jetty-server.jar
/usr/share/jigasi/lib/jetty-servlet.jar
/usr/share/jigasi/lib/jetty-util.jar
/usr/share/jigasi/lib/jetty-webapp.jar
/usr/share/jigasi/lib/jetty-xml.jar
/usr/share/jigasi/lib/jicoco.jar
/usr/share/jigasi/lib/jitsi-android-osgi.jar
/usr/share/jigasi/lib/jitsi-argdelegation.jar
/usr/share/jigasi/lib/jitsi-certificate.jar
/usr/share/jigasi/lib/jitsi-configuration.jar
/usr/share/jigasi/lib/jitsi-contactlist.jar
/usr/share/jigasi/lib/jitsi-credentialsstorage.jar
/usr/share/jigasi/lib/jitsi-desktoputil.jar
/usr/share/jigasi/lib/jitsi-dns.jar
/usr/share/jigasi/lib/jitsi-dnsservice.jar
/usr/share/jigasi/lib/jitsi-fileaccess.jar
/usr/share/jigasi/lib/jitsi-globaldisplaydetails.jar
/usr/share/jigasi/lib/jitsi-hid.jar
/usr/share/jigasi/lib/jitsi-lgpl-dependencies.jar
/usr/share/jigasi/lib/jitsi-muc.jar
/usr/share/jigasi/lib/jitsi-neomedia.jar
/usr/share/jigasi/lib/jitsi-netaddr.jar
/usr/share/jigasi/lib/jitsi-notification-service.jar
/usr/share/jigasi/lib/jitsi-packetlogging.jar
/usr/share/jigasi/lib/jitsi-protocol-jabber.jar
/usr/share/jigasi/lib/jitsi-protocol.jar
/usr/share/jigasi/lib/jitsi-protocol-media.jar
/usr/share/jigasi/lib/jitsi-protocol-sip.jar
/usr/share/jigasi/lib/jitsi-reconnect.jar
/usr/share/jigasi/lib/jitsi-resourcemanager.jar
/usr/share/jigasi/lib/jitsi-sysactivity.jar
/usr/share/jigasi/lib/jitsi-systray-service.jar
/usr/share/jigasi/lib/jitsi-ui-service.jar
/usr/share/jigasi/lib/jitsi-util.jar
/usr/share/jigasi/lib/jitsi-version.jar
/usr/share/jigasi/lib/jna.jar
/usr/share/jigasi/lib/jnsapi.jar
/usr/share/jigasi/lib/json-simple.jar
/usr/share/jigasi/lib/jzlib.jar
/usr/share/jigasi/lib/laf-widget.jar
/usr/share/jigasi/lib/libidn.jar
/usr/share/jigasi/lib/libjitsi.jar
/usr/share/jigasi/lib/libunix.so
/usr/share/jigasi/lib/log4j.jar
/usr/share/jigasi/lib/orange-extensions.jar
/usr/share/jigasi/lib/org.apache.felix.framework.jar
/usr/share/jigasi/lib/org.apache.felix.main.jar
/usr/share/jigasi/lib/org.osgi.core.jar
/usr/share/jigasi/lib/sdes4j.jar
/usr/share/jigasi/lib/sdp-api.jar
/usr/share/jigasi/lib/sip-api-1.2.jar
/usr/share/jigasi/lib/slf4j-api.jar
/usr/share/jigasi/lib/slf4j-jdk14.jar
/usr/share/jigasi/lib/smack.jar
/usr/share/jigasi/lib/smackx.jar
/usr/share/jigasi/lib/tinder.jar
/usr/share/jigasi/lib/unix.jar
/usr/share/jigasi/lib/weupnp.jar
/usr/share/jigasi/lib/xml-apis.jar
/usr/share/jigasi/lib/xmlpull.jar
/usr/share/jigasi/lib/xpp3.jar
/usr/share/jigasi/lib/zrtp4j-light.jar
/usr/share/jigasi/lib/logging.properties
/usr/share/jigasi/lib/native
#/usr/share/jigasi/lib/native/linux-64
/usr/share/jigasi/lib/native/linux-64/libhwaddressretriever.so
%pre
if id -u "jigasi" >/dev/null 2>&1; then
	echo "account \"jigasi\" exists"
else
	if grep -q "^${jitsi}:" /etc/group; then
		echo "group \"jitsi\" exists"
	else
		groupadd jitsi
	fi
	mkdir -p /usr/share/jigasi
	useradd -c "jigasi ,,," -m -g jitsi -s /bin/false  -d /usr/share/jigasi jigasi
	chown jigasi:jitsi /usr/share/jigasi
	if [ ! -d "/var/log/jitsi" ]; then
		mkdir -p /var/log/jitsi
		chown jigasi:jitsi /var/log/jitsi
	fi
fi
