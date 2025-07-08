import * as OTPAuth from 'otpauth';

export type Otp = {
	secret: string;
	algorithm: string;
	digits: number;
	period: number;
	issuer: string | null;
};

export function from_uri(uri: string) {
	const parts = new URL(uri);
	const queryObject = Object.fromEntries(parts.searchParams.entries());
	if (!uri.includes('totp')) return null;
	if (!queryObject.secret) return null;
	const algorithm = queryObject.algorithm ? queryObject.algorithm : 'SHA1';
	const digits = parseInt(queryObject.digits ? queryObject.digits : '6');
	const period = parseInt(queryObject.period ? queryObject.period : '30');
	const issuer: string | null = queryObject.issuer ? queryObject.issuer : null;
	const otp = {
		secret: queryObject.secret,
		algorithm: algorithm,
		digits: digits,
		period: period,
		issuer: issuer
	};
	return otp;
}

export function generate(otp: Otp) {
	const totp = new OTPAuth.TOTP({
		secret: otp.secret,
		algorithm: otp.algorithm,
		digits: otp.digits,
		period: otp.period,
		issuer: otp.issuer ? otp.issuer : undefined
	});
	return totp.generate();
}
