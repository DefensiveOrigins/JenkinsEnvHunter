
import java.nio.charset.StandardCharsets;
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
      com.cloudbees.plugins.credentials.Credentials.class
)

for (c in creds) {
  println(c.id)
  if (c.properties.description) {
    println("   description: " + c.description)
  }
  if (c.properties.username) {
    println("   username: " + c.username)
  }
  if (c.properties.password) {
    println("   password: " + c.password)
  }
  if (c.properties.passphrase) {
    println("   passphrase: " + c.passphrase)
  }
  if (c.properties.secret) {
    println("   secret: " + c.secret)
  }
  if (c.properties.secretBytes) {
    println("    secretBytes: ")
    println("\n" + new String(c.secretBytes.getPlainData(), StandardCharsets.UTF_8))
    println("")
  }
  if (c.properties.privateKeySource) {
    println("   privateKey: " + c.getPrivateKey())
  }
  if (c.properties.apiToken) {
    println("   apiToken: " + c.apiToken)
  }
  if (c.properties.token) {
    println("   token: " + c.token)
  }
  if (c.properties.subscriptionId) {
    println("   subscriptionId: " + c.subscriptionId)
  }
  if (c.properties.clientId) {
    println("   clientId: " + c.clientId)
  }
  if (c.properties.tenant) {
    println("   tenant: " + c.tenant)
  }
  if (c.properties.clientSecret) {
    println("   clientSecret: " + c.clientSecret)
  }
  if (c.properties.plainClientSecret) {
    println("   plainClientSecret: " + c.plainClientSecret)
  }
  println("")
}
