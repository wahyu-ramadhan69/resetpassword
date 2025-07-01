import { NextResponse } from "next/server";
import { Client } from "ldapts";

const LDAP_URL = "ldap://192.168.29.12";
const ADMIN_DN = "CN=Tri Ade Putra,OU=staff,OU=group,DC=BCAFWIFI,DC=CO,DC=ID";
const ADMIN_PASSWORD = process.env.AD_ADMIN_PASSWORD;

export async function POST(req) {
  const { username, oldPassword, newPassword } = await req.json();

  if (!username || !oldPassword || !newPassword) {
    return NextResponse.json(
      { error: "❗ Input tidak lengkap." },
      { status: 400 }
    );
  }

  const client = new Client({ url: LDAP_URL });
  const userDN = `CN=${username},OU=staff,OU=group,DC=BCAFWIFI,DC=CO,DC=ID`;

  try {
    // Step 1: Bind pakai old password → cek valid tidak
    try {
      await client.bind(userDN, oldPassword);
      await client.unbind();
    } catch (authError) {
      return NextResponse.json(
        { error: "⚠️ Password lama salah." },
        { status: 401 }
      );
    }

    // Step 2: Bind sebagai admin
    await client.bind(ADMIN_DN, ADMIN_PASSWORD);

    // Format password: UTF-16LE dan dikelilingi tanda kutip
    const quotedPassword = `"${newPassword}"`;
    const utf16Password = Buffer.from(quotedPassword, "utf16le");

    await client.modify(userDN, [
      {
        operation: "replace",
        modification: {
          unicodePwd: utf16Password,
        },
      },
    ]);

    await client.unbind();
    return NextResponse.json({ message: "✅ Password berhasil diubah." });
  } catch (err) {
    return NextResponse.json(
      {
        error: "❌ Gagal mengubah password.",
        detail: err.message,
      },
      { status: 500 }
    );
  }
}
