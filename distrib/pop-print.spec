Name:           pop-print
Version:        0.1.0
Release:        1%{?dist}
Summary:        Web frontend for printing

License:        MIT
URL:            https://github.com/netgrp/pop-print
Source0:        %{name}-%{version}.tar.gz

# Rust toolchain is needed at build time only.
# The compiled binary has no runtime Rust dependency.
BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  systemd-rpm-macros

Requires:       systemd

# Prevent RPM from trying to find Rust-internal provides/requires
%global __cargo_skip_build 0

%global debug_package %{nil}

%description
pop-print is a web frontend for printing.

# ---------------------------------------------------------------------------
# Prep: unpack the source tarball
# ---------------------------------------------------------------------------
%prep
%autosetup -n %{name}-%{version}

# ---------------------------------------------------------------------------
# Build: compile with Cargo in release mode
# ---------------------------------------------------------------------------
%build
cargo build --release --locked

# ---------------------------------------------------------------------------
# Install: place files into the buildroot
# ---------------------------------------------------------------------------
%install
# Binary
install -D -m 0755 target/release/%{name} \
    %{buildroot}/%{_bindir}/%{name}

# systemd unit file (expected at upstream path: %{name}.service)
install -D -m 0644 %{name}.service \
    %{buildroot}/%{_unitdir}/%{name}.service

# ---------------------------------------------------------------------------
# Pre/post scriptlets for systemd integration
# ---------------------------------------------------------------------------
%pre
# Create a dedicated system user/group for the service
getent group %{name} &>/dev/null  || groupadd -r %{name}
getent passwd %{name} &>/dev/null || \
    useradd -r -g %{name} -d /var/lib/%{name} -s /sbin/nologin \
            -c "%{name} service account" %{name}
exit 0

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
