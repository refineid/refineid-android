# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Shared build-environment resolution for hook and helper scripts. Sourced,
# not executed: exports JAVA_HOME and puts the rustup-managed toolchain on
# PATH when the shell that invoked git lacks them (GUI clients, hooks).

if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME:-}/bin/java" ]; then
  if [ "$(uname)" = "Darwin" ]; then
    studio_jdk="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
    if [ -x "${studio_jdk}/bin/java" ]; then
      export JAVA_HOME="${studio_jdk}"
    elif [ -x "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/bin/java" ]; then
      export JAVA_HOME="/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home"
    elif [ -x "/usr/local/opt/openjdk/libexec/openjdk.jdk/Contents/Home/bin/java" ]; then
      export JAVA_HOME="/usr/local/opt/openjdk/libexec/openjdk.jdk/Contents/Home"
    elif command -v brew > /dev/null 2>&1; then
      brew_jdk="$(brew --prefix openjdk 2> /dev/null)/libexec/openjdk.jdk/Contents/Home"
      if [ -x "${brew_jdk}/bin/java" ]; then
        export JAVA_HOME="${brew_jdk}"
      fi
    fi
  fi
fi

if [ -n "${JAVA_HOME:-}" ] && [ -d "${JAVA_HOME}/bin" ]; then
  case ":${PATH}:" in
    *":${JAVA_HOME}/bin:"*) ;;
    *) export PATH="${JAVA_HOME}/bin:${PATH}" ;;
  esac
fi

if [ -d "${HOME}/.cargo/bin" ]; then
  case ":${PATH}:" in
    *":${HOME}/.cargo/bin:"*) ;;
    *) export PATH="${HOME}/.cargo/bin:${PATH}" ;;
  esac
fi
