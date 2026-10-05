%{!?_unitdir: %define _unitdir /usr/lib/systemd/system}

Name:           aether
Version:        @@VERSION@@
Release:        1%{?dist}
Summary:        High-assurance Linux threat hunter and forensic triage engine
License:        Proprietary
URL:            https://github.com/aether/aether

%description
Aether is an executive-grade, forensic-safe, read-only Linux threat hunting
and anomaly detection engine. It performs deep static heuristic analysis,
process/network correlation, and package integrity verification.

%prep

%build

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/aether/rules
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_mandir}/man1
mkdir -p %{buildroot}%{_localstatedir}/log/aether

install -m 0755 %{_sourcedir}/bin/aether %{buildroot}%{_bindir}/aether
install -m 0644 %{_sourcedir}/config.yaml %{buildroot}%{_sysconfdir}/aether/config.yaml
install -m 0644 %{_sourcedir}/packaging/systemd/aether-scan.service %{buildroot}%{_unitdir}/aether-scan.service
install -m 0644 %{_sourcedir}/packaging/systemd/aether-scan.timer %{buildroot}%{_unitdir}/aether-scan.timer
install -m 0644 %{_sourcedir}/man/man1/aether*.1 %{buildroot}%{_mandir}/man1/

%post
if [ $1 -eq 1 ]; then
    # Initial installation: reload systemd manager configuration
    systemctl daemon-reload >/dev/null 2>&1 || :
    # Timer is NOT automatically enabled (opt-in per FR-015 / FR-024)
fi

%preun
if [ $1 -eq 0 ]; then
    # Package removal: stop and disable units (FR-018)
    systemctl stop aether-scan.timer aether-scan.service >/dev/null 2>&1 || :
    systemctl disable aether-scan.timer >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
# Note: /var/log/aether reports and user audit data are preserved (FR-017)

%files
%{_bindir}/aether
%dir %{_sysconfdir}/aether
%dir %{_sysconfdir}/aether/rules
%config(noreplace) %{_sysconfdir}/aether/config.yaml
%{_unitdir}/aether-scan.service
%{_unitdir}/aether-scan.timer
%{_mandir}/man1/aether*.1*
%ghost %dir %{_localstatedir}/log/aether
