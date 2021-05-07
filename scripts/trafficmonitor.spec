# The name should reflect the name part of the tar.gz archive
Name:           trafficmonitor
# The version should reflect the version part of the tar.gz arcive
Version:        0.3.1
Release:        0
Summary:        Package for the trafficmonitor

License:        GPLv3+
URL:            https://github.com/RaaLabs/trafficmonitor

# The name of the tar.gz archive as present in the SOURCE folder
Source0:        %{name}-%{version}-x86_64.tar.gz

Requires:       bash

# options x86_64 or noarch
BuildArch:      x86_64

%description
Traffic monitoring tool

%prep
%setup -q


%build

%install
# Prepare the binary and run script
install -d -m 0755 %{buildroot}/usr/local/trafficmonitor
install -m 0755 trafficmonitor %{buildroot}/usr/local/trafficmonitor/trafficmonitor
install -m 0755 scripts/run.sh %{buildroot}/usr/local/trafficmonitor/run.sh

# Prepare the systemd files
mkdir -p %{buildroot}/usr/lib/systemd/system/
install -m 0755 scripts/trafficmonitor.service %{buildroot}/usr/lib/systemd/system/trafficmonitor.service
mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
ln -s /usr/lib/systemd/system/trafficmonitor.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/trafficmonitor.service

# Prepare a link to the service within clr-service-restart so it will be automatically restarted when updated
mkdir -p %{buildroot}/usr/share/clr-service-restart
ln -sf /usr/lib/systemd/system/trafficmonitor.service %{buildroot}/usr/share/clr-service-restart/trafficmonitor.service

%files
# %license LICENSE
/usr/local/trafficmonitor/trafficmonitor
/usr/local/trafficmonitor/run.sh
/usr/share/clr-service-restart/trafficmonitor.service
/usr/lib/systemd/system/trafficmonitor.service
/usr/lib/systemd/system/multi-user.target.wants/trafficmonitor.service