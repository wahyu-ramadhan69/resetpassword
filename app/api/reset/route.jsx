import { NextResponse } from "next/server";
import { Client } from "ldapts";

const LDAP_URL = "ldap://192.168.29.12";
const ADMIN_DN = "CN=Tri Ade Putra,OU=staff,OU=group,DC=BCAFWIFI,DC=CO,DC=ID";
const ADMIN_PASSWORD = process.env.AD_ADMIN_PASSWORD;
const BASE_DN = "DC=BCAFWIFI,DC=CO,DC=ID";

export async function POST(req) {
  const { username, oldPassword, newPassword } = await req.json();

  if (!username || !oldPassword || !newPassword) {
    return NextResponse.json(
      { error: "❗ Input tidak lengkap." },
      { status: 400 }
    );
  }

  const client = new Client({ url: LDAP_URL });

  try {
    await client.bind(ADMIN_DN, ADMIN_PASSWORD);

    const { searchEntries } = await client.search(BASE_DN, {
      scope: "sub",
      filter: `(sAMAccountName=${username})`,
      attributes: ["distinguishedName"],
    });

    if (searchEntries.length === 0) {
      return NextResponse.json(
        { error: "❌ User tidak ditemukan." },
        { status: 404 }
      );
    }

    const userDN = searchEntries[0].distinguishedName;

    // Bind sebagai user dengan old password
    try {
      await client.bind(userDN, oldPassword);
    } catch {
      return NextResponse.json(
        { error: "⚠️ Password lama salah." },
        { status: 401 }
      );
    }

    // Bind ulang sebagai admin
    await client.bind(ADMIN_DN, ADMIN_PASSWORD);

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
      { error: "❌ Gagal mengubah password.", detail: err.message },
      { status: 500 }
    );
  }
}
