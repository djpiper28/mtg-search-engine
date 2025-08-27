import { type Card } from "../../../model/card";
import { defaultApiUrl } from "../../apiDefaultUrl";
import Manamoji from "../../../components/manamoji";
import Oracle from "../../../components/oracle";
import Colour from "../../../components/colour";
import Setmoji from "../../../components/setmoji";
import { TypeLine } from "../../../components/typeLine";
import { Legality } from "../../../components/legality";

export const dynamic = "force-dynamic";

interface Props {
  params: Promise<{
    id: string;
  }>;
}

export default async function Page(props: Readonly<Props>) {
  const params = await props.params;
  const resp = await fetch(
    (process.env.BACKEND_URL ?? defaultApiUrl) + "/card_id",
    {
      method: "POST",
      body: params.id,
    },
  );

  let data: Card;
  if (resp.ok) {
    data = await resp.json();
  } else {
    return <p>There was an error: {await resp.text()}</p>;
  }

  const colours = [];
  for (var i = 1; i < 1 << 5; i <<= 1) {
    const c = data.colour_identity & i;
    if (c) {
      colours.push(c);
    }
  }

  let sets = data.sets.map((x) => (
    <Setmoji code={x} key={`sets-${x}-${data.id}`} />
  ));

  return (
    <div className="flex flex-col gap-5 bg-white p-3 md:p-5 rounded-xl justify-between w-full">
      <div className="flex flex-row gap-3 justify-between">
        <h1 className="text-2xl font-bold hyphens-auto text-wrap">{data.name}</h1>
        <div className="flex flex-row flex-wrap w-max justify-end">
          {data.mana_cost &&
            data.mana_cost
              .split("{")
              .slice(1)
              .map((mana, i) => (
                <Manamoji
                  large={true}
                  mana_cost={mana.replace("}", "")}
                  key={`mana-${mana}-${i}-${data.id}`}
                />
              ))}
        </div>
      </div>
      {data.types && <TypeLine types={data.types} />}
      {data.oracle_text && (
        <Oracle oracle_text={data.oracle_text} id={data.name} large={true} />
      )}
      <div className="grow" />
      <div className="flex flex-row justify-between">
        <div className="flex flex-row gap-1 items-center">
          Colour identity:
          {colours.map((c) => (
            <Colour colour={c} key={`colours-${c}-${data.id}`} />
          ))}
        </div>
        <span>
          <p className="text-right">
            {data.power && data.toughness
              ? data.power + "/" + data.toughness
              : ""}
          </p>
          <p className="text-right">
            {data.loyalty ? `Loyalty: ${data.loyalty}` : ""}
          </p>
        </span>
      </div>
      <div className="grid md:grid-cols-2 gap-2 gap-x-5">
        {Object.keys(data.format_legalities).map((format) => {
          const legality = data.format_legalities[format];

          return <Legality format={format} legality={legality} />;
        })}
      </div>
      <div className="flex flex-row flex-wrap gap-1">
        <p>Printed in {sets.length} Sets:</p> {sets}
      </div>
    </div>
  );
}
