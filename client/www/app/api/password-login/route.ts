// EPL fork: password-only dashboard login. See lib/passwordLogin.server.ts.
import { NextRequest, NextResponse } from 'next/server';
import {
  passwordLogin,
  PasswordLoginError,
} from '@/lib/passwordLogin.server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function clientKey(req: NextRequest) {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    'unknown'
  );
}

export async function POST(req: NextRequest) {
  let password: unknown;
  try {
    ({ password } = await req.json());
  } catch {
    password = undefined;
  }
  if (typeof password !== 'string' || !password) {
    return NextResponse.json(
      { type: 'param-missing', message: 'Password is required' },
      { status: 400 },
    );
  }

  try {
    const result = await passwordLogin(password, clientKey(req));
    return NextResponse.json(result);
  } catch (e) {
    if (e instanceof PasswordLoginError) {
      return NextResponse.json(
        { type: e.type, message: e.message },
        { status: e.status },
      );
    }
    console.error('[password-login] unexpected error', e);
    return NextResponse.json(
      { type: 'upstream', message: 'Login failed' },
      { status: 500 },
    );
  }
}
