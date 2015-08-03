PKG_VERSION = 0.2.1
FLATPKG_IDENTITY = Y28TH9SHX7

all: package update_git update_cache

build:
	cd "Marionette Bootstrap" && xcodebuild

package: build
	rm -rf "Marionette Bootstrap"/build/pkgroot
	mkdir -p "Marionette Bootstrap/build/pkgroot/Library/Application Support/Stripe/Applications"
	mkdir -p "Marionette Bootstrap/build/pkgroot/Library/LaunchAgents"
	rsync -avp --delete "./Marionette Bootstrap/build/Release/Marionette Bootstrap.app" "Marionette Bootstrap/build/pkgroot/Library/Application Support/Stripe/Applications/"
	cp "Marionette Bootstrap/com.stripe.it.mac.yoyo-bootstrap.plist" "Marionette Bootstrap/build/pkgroot/Library/LaunchAgents"
	pkgbuild --identifier com.stripe.it.mac.yoyo.bootstrap --version ${PKG_VERSION} --root "Marionette Bootstrap"/build/pkgroot --component-plist "Marionette Bootstrap"/component.plist "Marionette Bootstrap/build/bootstrap.component-${PKG_VERSION}.pkg"
	productbuild --package "Marionette Bootstrap/build/bootstrap.component-${PKG_VERSION}.pkg" --sign ${FLATPKG_IDENTITY} "Marionette Bootstrap/build/Marionette Bootstrap-${PKG_VERSION}.pkg"

update_git: init_usbdrive
	for i in "/Volumes/Marionette Cache"*/"git" ; do \
		( ! [ -x "$$i"/git/update ] && ./git/bootstrap.sh "$$i" ; \
		"$$i"/update) & \
	done; wait

update_cache: init_usbdrive
	(cd cache && \
	for file in * ; do \
		../bin/cache-file "$$file" "/Volumes/Marionette Cache"*/ ; \
	done)

init_usbdrive:
	for target in "/Volumes/Marionette Cache"*/ ; do \
		if [ -d "$$target" ] ; then \
			mkdir -p "$$target"/{git,"Marionette Bootstrap.app",stripe-marionette} ; \
		else \
			echo "There doesn't seem to be a yoyo cache usb drive plugged in." ; \
			exit 1; \
		fi ; \
	done

eject:
	for i in "/Volumes/Marionette Cache"*/ ; do \
		diskutil eject "$$i"; \
	done
