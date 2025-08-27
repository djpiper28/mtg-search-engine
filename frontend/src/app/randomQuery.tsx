"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import searchUrlFor, { SortType } from "./searchUrl";

export default function RandomQuery() {
  const router = useRouter();
  const [query, setQuery] = useState("set:m20 or set:m19");
  const queries: string[] = [
    "c:r and name:goblin",
    "c:u and name:wizard and oracle:/.*draw(( a)|[0-9]) card(s)?.*/",
    "goblin motivator",
    "set:m20 and c:u",
    "hydra o:/^x?.*.?\\sx[., ].*$/ and legal:standard",
    "i:r -c:r",
    "-name:goblin c:r oracle:goblin",
    "-set:m20 set:m21",
    "(i:r -c:r) or i>rgb",
    'set:m19 and type:goblin and name:"motivator"',
    "name:/.*god of the.*/ and type:legendary and type:god and (oracle:indestructible or oracle:devotion)",
    "legal:commander and banned:modern",
    "type:goat and legal:commander",
    "o:banding and legal:commander and type:legendary",
    "dandan c:u",
  ];
  useEffect(() => {
    setInterval(() => {
      setQuery(queries[Math.floor(Math.random() * queries.length)]);
    }, 2000);
  }, []);

  return (
    <div className="flex flex-row">
      <h2 className="text-l">Powerful search engine, search for anything:</h2>
      <p
        className="px-3"
        onClick={() => {
          router.push(searchUrlFor(query, 1, SortType.CardName, true));
        }}
      >
        🔍 {query}
      </p>
    </div>
  );
}
