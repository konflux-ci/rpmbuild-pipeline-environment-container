Name:		dummy-pkg-muliple-tags
Version:	1.0
Release:	1%{?dist}
Summary:	A dummy package

License:	GPLv3+
URL:		http://example.com/

ExcludeArch:	weirdarch
ExcludeArch:	s390x
ExclusiveArch:	noarch
ExclusiveArch:	%java_arches
ExclusiveArch:	i686

%if 0%{?fedora}
ExclusiveArch: on-fedora-exclusivearch
ExcludeArch: on-fedora-excludearch
%endif

%if 0%{?rhel}
ExclusiveArch: on-rhel-exclusivearch
ExcludeArch: on-rhel-excludearch
%endif

BuildArch:	noarch

Source0:	https://raw.githubusercontent.com/praiskup/quick-package/master/README.xz


%description
Description for the %name package that is used for various testing tasks.


%prep


%build


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_pkgdocdir}
xz -d %{SOURCE0} --stdout > $RPM_BUILD_ROOT/%{_pkgdocdir}/README


%files
%dir %{_pkgdocdir}
%doc %{_pkgdocdir}/README


%changelog
* Thu Jun 05 2014 Pavel Raiskup <praiskup@redhat.com> - 0-1
- does nothing!
