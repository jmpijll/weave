enum UnsupportedServerSyntax {
  Value,
}

namespace UnsupportedServerNamespace {
  export const value = UnsupportedServerSyntax.Value;
}

class UnsupportedServerParameterProperty {
  constructor(private readonly value: string) {}

  getValue(): string {
    return this.value;
  }
}

console.log(
  UnsupportedServerNamespace.value,
  new UnsupportedServerParameterProperty("server").getValue(),
);
