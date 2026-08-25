# Homebrew formula. Lives in a tap: homebrew-netinspect/Formula/netinspect.rb.
#
# Most people will install this way, and `netinspect update` deliberately
# refuses to fight brew over its own files — it says `brew upgrade netinspect`
# instead.
class Netinspect < Formula
  desc "Read-only network diagnostics: configuration, reachability, public address"
  homepage "https://github.com/pottom/netinspect"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/pottom/netinspect/releases/download/v#{version}/netinspect-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "945b9175545a3abfbb4786ba9af0f2b507fb1de4acd2181d22b71ac88e372fc4"
    end
    on_intel do
      url "https://github.com/pottom/netinspect/releases/download/v#{version}/netinspect-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "945b9175545a3abfbb4786ba9af0f2b507fb1de4acd2181d22b71ac88e372fc4"
    end
  end

  def install
    bin.install "netinspect"
    generate_completions_from_executable(bin/"netinspect", "completions")
  end

  test do
    assert_match "netinspect v#{version}", shell_output("#{bin}/netinspect --version")
    # It reports successfully whatever the network is doing; only `check`
    # encodes connectivity in its exit code.
    system bin/"netinspect", "--json", "--no-lookup", "--no-check"
  end
end
