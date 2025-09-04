Name:		dummy-pkg-exclude-exclusive-arch
Version:	1.0
Release:	1%{?dist}
Summary:	A dummy package

License:	GPLv3+
URL:		http://example.com/
ExcludeArch:	s390x
ExclusiveArch:	%java_arches

Source0:	https://raw.githubusercontent.com/praiskup/quick-package/master/README.xz


%description
Description for the %name package that is used for various testing tasks.


%prep


%build


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_pkgdocdir}
xz -d %{SOURCE0} --stdout > $RPM_BUILD_ROOT/%{_pkgdocdir}/README


%clean
rm -rf $RPM_BUILD_ROOT


%files
%dir %{_pkgdocdir}
%doc %{_pkgdocdir}/README

%changelog
* Thu Jun 05 2014 Pavel Raiskup <praiskup@redhat.com> - 0-1
- does nothing!
