# Homebrew formula for udp-broadcast-relay-redux (Rust port).
# To publish: create a tap repository github.com/zhuzhuzihan/homebrew-tap,
# copy this file to Formula/udp-broadcast-relay-redux.rb, then:
#   brew tap zhuzhuzihan/tap && brew install udp-broadcast-relay-redux
# Replace the sha256 values with the release asset checksums.
class UdpBroadcastRelayRedux < Formula
  desc "Relay UDP broadcasts to other networks, forging the sender address"
  homepage "https://github.com/zhuzhuzihan/udp-broadcast-relay-redux-rust"
  version "1.1.0"
  license "GPL-2.0-or-later"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/zhuzhuzihan/udp-broadcast-relay-redux-rust/releases/download/v#{version}/udp-broadcast-relay-redux-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/zhuzhuzihan/udp-broadcast-relay-redux-rust/releases/download/v#{version}/udp-broadcast-relay-redux-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    elsif Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/zhuzhuzihan/udp-broadcast-relay-redux-rust/releases/download/v#{version}/udp-broadcast-relay-redux-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  def install
    bin.install "udp-broadcast-relay-redux"
    man1.install "docs/udp-broadcast-relay-redux.1" if (buildpath/"docs/udp-broadcast-relay-redux.1").exist?
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/udp-broadcast-relay-redux --version")
  end
end
