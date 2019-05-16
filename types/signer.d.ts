interface RequestData {
  method: string;
  url: string;
  data?: { [key: string]: any };
}

interface Token {
  public?: string;
  secret?: string;
  [key: string]: any;
}
