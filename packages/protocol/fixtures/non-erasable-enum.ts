enum UnsupportedProtocolSyntax {
  Value,
}

namespace UnsupportedProtocolNamespace {
  export const value = UnsupportedProtocolSyntax.Value;
}

class UnsupportedProtocolParameterProperty {
  constructor(private readonly value: string) {}

  getValue(): string {
    return this.value;
  }
}

console.log(
  UnsupportedProtocolNamespace.value,
  new UnsupportedProtocolParameterProperty("protocol").getValue(),
);
