// app/api/change-password/route.ts
import { NextResponse } from "next/server";
import { Client } from "ldap-client";

const ldapConfig = {
  url: "ldap://192.168.29.12",
  bindDN: "CN=Tri Ade Putra,OU=staff,OU=group,DC=BCAFWIFI,DC=CO,DC=ID",
  bindCredentials: "1234Qwer",
  baseDN: "DC=BCAFWIFI,DC=CO,DC=ID",
};

export async function POST(req) {
  const { username, oldPassword, newPassword } = await req.json();

  if (!username || !oldPassword || !newPassword) {
    return NextResponse.json(
      { error: "❗ Input tidak lengkap." },
      { status: 400 }
    );
  }

  const userPrincipalName = `${username}@BCAFWIFI.CO.ID`; // Format UPN
  const userDN = `CN=${username},OU=staff,OU=group,DC=BCAFWIFI,DC=CO,DC=ID`; // Sesuaikan jika struktur OU beda

  const adminClient = new Client({
    url: ldapConfig.url,
    bindDN: ldapConfig.bindDN,
    bindCredentials: ldapConfig.bindCredentials,
  });

  const userClient = new Client({
    url: ldapConfig.url,
    bindDN: userPrincipalName,
    bindCredentials: oldPassword,
  });

  try {
    // Step 1: Validasi password lama (bind sebagai user)
    await userClient.bind();

    // Step 2: Bind sebagai admin untuk ubah password
    await adminClient.bind();

    // Step 3: Ubah password
    await adminClient.modifyPassword(userDN, {
      oldPassword,
      newPassword,
    });

    return NextResponse.json({ message: "✅ Password berhasil diubah." });
  } catch (error) {
    let friendly = "❌ Gagal mengubah password.";
    if (error?.code === 49) {
      friendly = "⚠️ Password lama salah.";
    }
    return NextResponse.json(
      {
        error: friendly,
        detail: error?.message || String(error),
      },
      { status: 500 }
    );
  } finally {
    await adminClient.unbind();
    await userClient.unbind();
  }
}
