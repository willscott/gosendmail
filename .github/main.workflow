workflow "Go" {
  on = "pull_request"
  resolves = [
    "gofmt",
    "gobuild",
  ]
}

action "gofmt" {
  uses = "sjkaliski/go-github-actions/fmt@v0.4.0"
  secrets = ["GITHUB_TOKEN"]
  env = {
    GO_WORKING_DIR = "./..."
  }
}

action "gobuild" {
  uses = "cedrickring/golang-action@1.3.0"
  needs = "gofmt"
  # optional build command:
  args = "go build ./cmd/signmail ./cmd/sendmail"
}