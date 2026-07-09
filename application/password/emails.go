package password

import "fmt"

func verificationEmail(link string) (subject, html string) {
	subject = "Verify your Drafted email"
	html = fmt.Sprintf(`<p>Welcome to Drafted!</p>
<p>Confirm your email address to finish setting up your account:</p>
<p><a href="%[1]s">Verify email</a></p>
<p>Or paste this link into your browser: %[1]s</p>
<p>This link expires in 24 hours. If you didn't create a Drafted account, you can ignore this email.</p>`, link)
	return subject, html
}

func passwordResetEmail(link string) (subject, html string) {
	subject = "Reset your Drafted password"
	html = fmt.Sprintf(`<p>We received a request to reset your Drafted password.</p>
<p><a href="%[1]s">Reset password</a></p>
<p>Or paste this link into your browser: %[1]s</p>
<p>This link expires in 1 hour. If you didn't request a reset, you can ignore this email — your password is unchanged.</p>`, link)
	return subject, html
}
