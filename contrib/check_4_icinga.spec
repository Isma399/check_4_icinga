Name:           check-4-icinga
Version:        0.0.1
Release:        1%{?dist}
Summary:        SNMP checks for linux devices

License: GPL
URL: https://github.com/Isma399/check_4_icinga            
Source: %{name}-%{version}.tar.gz

%description
SNMP checks for linux devices, written in C, made for Icinga.

%prep

%setup -q

mkdir build

%build
pushd build
%cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} -DCMAKE_BUILD_TYPE=Release ../
popd

%install
pushd build
%make_install
popd

%files
%defattr(0644, root, root, 0755)

%attr(0755, -, -) %{_libdir}/nagios/plugins/check_linux_disk
%attr(0755, -, -) %{_libdir}/nagios/plugins/check_linux_inode
%attr(0755, -, -) %{_libdir}/nagios/plugins/check_linux_load
%attr(0755, -, -) %{_libdir}/nagios/plugins/check_linux_ram

%config %{_datadir}/icinga2/include/plugins-contrib.d/linux.conf