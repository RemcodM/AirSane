FROM debian:unstable

ADD . /app/

RUN apt-get update && \
	apt-get dist-upgrade -y && \
	apt-get install -y --no-install-recommends sane build-essential cmake git ca-certificates libsane-dev libjpeg-dev libpng-dev libavahi-client-dev libusb-1.0-0-dev && \
	export BUILD_DIR="$(mktemp -d)" && \
	cd "${BUILD_DIR}" && \
	cmake /app && \
	make && \
	make install && \
	cd / && \
	rm -rf "${BUILD_DIR}" && \
	rm -rf /app && \
	apt-get purge -y build-essential cmake git ca-certificates libsane-dev libjpeg-dev libpng-dev libavahi-client-dev libusb-1.0-0-dev && \
	apt-get --purge autoremove -y && \
	apt-get clean -y && \
	rm -f /etc/sane.d/net.conf && \
	echo "net" > /etc/sane.d/dll.conf

VOLUME ["/etc/sane.d/net.conf"]
EXPOSE 8090

CMD /usr/local/bin/airsaned --interface=* --listen-port=8090 --access-log= --hotplug=true --mdns-announce=false --local-scanners-only=false --debug=true
