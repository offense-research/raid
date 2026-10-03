# Homebrew formula for Raid.
#
# Install from this repository (no separate tap needed):
#
#   brew install --formula ./packaging/homebrew/raid.rb
#
# Or tap it so `brew install raid` works by name:
#
#   brew tap offense-research/raid https://github.com/offense-research/raid
#   brew install raid
#
# `brew tap <user>/<repo>` expects the repo to be named `homebrew-<repo>`; the
# explicit URL form above works for any repo name.
#
# The formula builds from the tagged source tarball. The store uses a cgo
# SQLite driver, so the build uses the system toolchain Homebrew provides
# (Xcode CLT on macOS, build-essential on Linux) and depends on Go.
class Raid < Formula
  desc "Deterministic policy and approval engine that gates coding-agent actions"
  homepage "https://github.com/offense-research/raid"
  url "https://github.com/offense-research/raid/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "34a0aff6ac943728045b1d49083e163b8bf6724843edbf974a558235c473d842"
  license "Apache-2.0"
  head "https://github.com/offense-research/raid.git", branch: "main"

  depends_on "go" => :build

  def install
    # -s -w strips symbols, matching the release binaries.
    system "go", "build", *std_go_args(ldflags: "-s -w"), "-o", bin/"raid", "."
    # The daemon is the same binary; raidd selects server mode by argv[0].
    bin.install_symlink "raid" => "raidd"
    # Example policies, docs, and the API schemas for local reference.
    pkgshare.install "examples", "docs", "api"
  end

  test do
    assert_match "raid", shell_output("#{bin}/raid version")
    assert_path_exists bin/"raidd"
  end
end
