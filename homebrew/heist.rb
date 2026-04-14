# Homebrew formula for heist.
#
# This file lives in a tap repository at:
#   https://github.com/iamdainwi/homebrew-tap
#
# Install:
#   brew install iamdainwi/tap/heist
#
# To update the formula after a new release, update `version`, `url`, and
# both `sha256` values. The sha256 values come from the .sha256 files
# attached to each GitHub Release.

class Heist < Formula
  desc "Secure, encrypted secrets manager for the terminal"
  homepage "https://github.com/iamdainwi/heist"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/iamdainwi/heist/releases/download/v#{version}/heist-macos-aarch64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_PAGE"
    end
    on_intel do
      url "https://github.com/iamdainwi/heist/releases/download/v#{version}/heist-macos-x86_64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_PAGE"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/iamdainwi/heist/releases/download/v#{version}/heist-linux-aarch64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_PAGE"
    end
    on_intel do
      url "https://github.com/iamdainwi/heist/releases/download/v#{version}/heist-linux-x86_64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_PAGE"
    end
  end

  def install
    bin.install "heist"
  end

  # Generate shell completions during install.
  def post_install
    (bash_completion/"heist").write Utils.safe_popen_read(bin/"heist", "completion", "bash")
    (zsh_completion/"_heist").write Utils.safe_popen_read(bin/"heist", "completion", "zsh")
    (fish_completion/"heist.fish").write Utils.safe_popen_read(bin/"heist", "completion", "fish")
  end

  test do
    assert_match "heist #{version}", shell_output("#{bin}/heist --version")
  end
end
