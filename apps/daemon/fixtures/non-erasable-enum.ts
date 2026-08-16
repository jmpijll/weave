enum UnsupportedDaemonSyntax {
  Value,
}

namespace UnsupportedDaemonNamespace {
  export const value = UnsupportedDaemonSyntax.Value;
}

class UnsupportedDaemonParameterProperty {
  constructor(private readonly value: string) {}

  getValue(): string {
    return this.value;
  }
}

console.log(
  UnsupportedDaemonNamespace.value,
  new UnsupportedDaemonParameterProperty("daemon").getValue(),
);
