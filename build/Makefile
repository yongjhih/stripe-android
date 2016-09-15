PKG_VERSION = 0.3.3
FLATPKG_IDENTITY = Y28TH9SHX7

all: package

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
