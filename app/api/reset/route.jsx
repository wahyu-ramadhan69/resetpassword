import { NextResponse } from "next/server";
import ActiveDirectory from "activedirectory2";

const config = {
  url: "ldap://192.168.29.12",
  baseDN: "DC=BCAFWIFI,DC=CO,DC=ID",
  username: "CN=Tri Ade Putra,OU=staff,OU=group,DC=BCAFWIFI,DC=CO,DC=ID",
  password: process.env.AD_ADMIN_PASSWORD,
};

const ad = new ActiveDirectory(config);

export async function POST(req) {
  const { username, oldPassword, newPassword } = await req.json();

  if (!username || !oldPassword || !newPassword) {
    return NextResponse.json(
      { error: "❗ Input tidak lengkap." },
      { status: 400 }
    );
  }

  try {
    // 🧠 Step 1: Verifikasi password lama (bind pakai sAMAccountName)
    const isValid = await new Promise((resolve, reject) => {
      ad.authenticate(username, oldPassword, (err, auth) => {
        if (err) return reject(err);
        resolve(auth);
      });
    });

    if (!isValid) {
      return NextResponse.json(
        { error: "⚠️ Password lama salah." },
        { status: 401 }
      );
    }

    // 🔁 Step 2: Ubah password
    const changeResult = await new Promise((resolve, reject) => {
      ad.findUser(username, (err, user) => {
        if (err || !user) return reject("User tidak ditemukan.");

        ad.setUserPassword(user.dn, newPassword, (err) => {
          if (err) return reject(err);
          resolve(true);
        });
      });
    });

    return NextResponse.json({ message: "✅ Password berhasil diubah." });
  } catch (err) {
    return NextResponse.json(
      {
        error: "❌ Gagal mengubah password.",
        detail: err.toString(),
      },
      { status: 500 }
    );
  }
}
