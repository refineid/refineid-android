# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Shared build-environment resolution for hook and helper scripts. Sourced,
# not executed, from the repository root. Exports JAVA_HOME as a JDK of the
# version the Gradle daemon requires (toolchainVersion in
# gradle/gradle-daemon-jvm.properties) and puts the rustup-managed toolchain
# on PATH, whatever the invoking shell carries (GUI clients, hooks, agents).
# With no such JDK on the machine it says so and leaves JAVA_HOME alone;
# Gradle then provisions the version from the file's download URLs.

refineid_daemon_jvm_properties="gradle/gradle-daemon-jvm.properties"
refineid_required_jdk=""
if [ -r "${refineid_daemon_jvm_properties}" ]; then
  refineid_required_jdk="$(sed -n 's/^toolchainVersion=\([0-9]*\).*/\1/p' "${refineid_daemon_jvm_properties}")"
fi

# The major version a JDK home declares in its release file; empty when the
# directory is not a JDK home.
refineid_jdk_major() {
  sed -n 's/^JAVA_VERSION="\([0-9]*\).*/\1/p' "$1/release" 2> /dev/null
}

# A JDK home of the required version, with its launcher as Unix or Windows
# (Git for Windows) names it.
refineid_jdk_matches() {
  { [ -x "$1/bin/java" ] || [ -x "$1/bin/java.exe" ]; } &&
    [ "$(refineid_jdk_major "$1")" = "${refineid_required_jdk}" ]
}

refineid_selected_jdk=""
if [ -z "${refineid_required_jdk}" ]; then
  echo "No toolchainVersion in ${refineid_daemon_jvm_properties}; run from the repository root." >&2
fi
for refineid_candidate_jdk in \
  "${JAVA_HOME:-}" \
  "/opt/homebrew/opt/openjdk@${refineid_required_jdk}/libexec/openjdk.jdk/Contents/Home" \
  "/usr/local/opt/openjdk@${refineid_required_jdk}/libexec/openjdk.jdk/Contents/Home" \
  "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home" \
  "/usr/local/opt/openjdk/libexec/openjdk.jdk/Contents/Home" \
  "/Applications/Android Studio.app/Contents/jbr/Contents/Home"; do
  if [ -n "${refineid_required_jdk}" ] && [ -n "${refineid_candidate_jdk}" ] &&
    refineid_jdk_matches "${refineid_candidate_jdk}"; then
    refineid_selected_jdk="${refineid_candidate_jdk}"
    break
  fi
done

if [ -n "${refineid_selected_jdk}" ]; then
  export JAVA_HOME="${refineid_selected_jdk}"
  case ":${PATH}:" in
    *":${JAVA_HOME}/bin:"*) ;;
    *) export PATH="${JAVA_HOME}/bin:${PATH}" ;;
  esac
elif [ -n "${refineid_required_jdk}" ]; then
  echo "No JDK ${refineid_required_jdk} found; install it (macOS: brew install openjdk@${refineid_required_jdk})" \
    "or Gradle downloads it." >&2
fi

# Prepended in turn, so Homebrew's keg-only rustup ends first on PATH, as
# Scripts/bootstrap-macos.sh orders it.
for refineid_rust_bin in "${HOME}/.cargo/bin" "/usr/local/opt/rustup/bin" "/opt/homebrew/opt/rustup/bin"; do
  if [ -d "${refineid_rust_bin}" ]; then
    case ":${PATH}:" in
      *":${refineid_rust_bin}:"*) ;;
      *) export PATH="${refineid_rust_bin}:${PATH}" ;;
    esac
  fi
done

unset refineid_daemon_jvm_properties refineid_required_jdk refineid_selected_jdk refineid_candidate_jdk refineid_rust_bin
unset -f refineid_jdk_major refineid_jdk_matches
