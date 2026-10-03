export const token = "github_pat_FAKE_TEST_TOKEN_12345678901234567890";

export async function execute(command: string) {
  return child_process.execSync(command);
}

export async function getRemote(url: string) {
  return fetch(url);
}
