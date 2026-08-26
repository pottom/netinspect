# Homebrew formula. Lives in a tap: homebrew-netinspect/Formula/netinspect.rb.
#
# Most people will install this way, and `netinspect update` deliberately
# refuses to fight brew over its own files — it says `brew upgrade netinspect`
# instead.
class Netinspect < Formula
  desc "Read-only network diagnostics: configuration, reachability, public address"
  homepage "https://github.com/pottom/netinspect"
  version "0.2.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/pottom/netinspect/releases/download/v#{version}/netinspect-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "658abb28bcc33c967521e9d60ceac1a811868a74329e88cc16d4e08d54350a5e"
    end
    on_intel do
      url "https://github.com/pottom/netinspect/releases/download/v#{version}/netinspect-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "f80ba96650eb66671df055e06f3d125c550bd059c619fd5350efb975a9e4b80c"
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
