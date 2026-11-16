/**
 * Captcha verification as a three-way verdict, so a provider outage is not
 * reported to the user as a failed challenge. Both `reject` and `unavailable`
 * refuse the request (fail closed); they differ only in the code the client
 * sees.
 *
 * Guide: Learn, "Captcha".
 */
export type CaptchaVerdict = 'pass' | 'reject' | 'unavailable';

/** The flow asking. With `checkAction`, the widget's action must equal it. */
export type CaptchaDoor = 'login' | 'register' | 'password-reset' | 'email-verification';

export interface CaptchaVerifier {
  verify(
    token: string | undefined,
    context: { ip?: string; door: CaptchaDoor },
  ): Promise<CaptchaVerdict>;
}
