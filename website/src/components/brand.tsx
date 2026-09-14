import Image from "next/image";
import Link from "next/link";

export function Brand({ href = "/" }: { href?: string }) {
  return (
    <Link className="brand" href={href} aria-label="UpsilonAuth home">
      <Image
        className="brand-symbol"
        src="/upsilonauth-logo.svg"
        alt=""
        width={28}
        height={28}
        priority
      />
      <span className="brand-name">UpsilonAuth</span>
    </Link>
  );
}
