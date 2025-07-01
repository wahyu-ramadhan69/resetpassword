import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import { Client } from "ldapts";
import path from "path";

const DOMAIN_CONTROLLER = "ldap://127.0.0.1";
const BASE_DN = "DC=BCAFWIFI,DC=CO,DC=ID";

export async function POST(req) {
  const { username, oldPassword, newPassword } = await req.json();

  if (!username || !oldPassword || !newPassword) {
    return NextResponse.json({ error: "Missing input" }, { status: 400 });
  }

  const userDN = `CN=${username},OU=staff,OU=group,${BASE_DN}`;

  try {
    // Step 1: Bind ke AD menggunakan username & old password
    const client = new Client({ url: DOMAIN_CONTROLLER });
    await client.bind(userDN, oldPassword);
    await client.unbind();

    console.log("password benar");

    // Step 2: Eksekusi PowerShell untuk ganti password
    const scriptPath = path.join(
      process.cwd(),
      "scripts",
      "reset-password.ps1"
    );

    const ps = spawn("powershell.exe", [
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      scriptPath,
      "-Username",
      username,
      "-PlainPassword",
      newPassword,
    ]);

    let stdout = "";
    let stderr = "";

    ps.stdout.on("data", (data) => (stdout += data.toString()));
    ps.stderr.on("data", (data) => (stderr += data.toString()));

    const exitCode =
      (await new Promise()) < number > ((resolve) => ps.on("close", resolve));

    if (exitCode !== 0) {
      return NextResponse.json(
        { error: stderr || "Reset failed" },
        { status: 500 }
      );
    }

    return NextResponse.json({
      message: "✅ Password berhasil diubah.",
      output: stdout,
    });
  } catch (err) {
    return NextResponse.json(
      {
        error: "❌ Password lama salah atau user tidak ditemukan.",
        detail: err.message,
      },
      { status: 401 }
    );
  }
}
