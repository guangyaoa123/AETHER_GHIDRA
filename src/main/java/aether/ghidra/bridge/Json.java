package aether.ghidra.bridge;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small dependency-free JSON codec for the local bridge protocol. */
public final class Json {
	private Json() {
	}

	public static Object parse(String value) {
		Parser parser = new Parser(value);
		Object result = parser.parseValue();
		parser.skipWhitespace();
		if (!parser.atEnd()) {
			throw new IllegalArgumentException("Trailing JSON content");
		}
		return result;
	}

	@SuppressWarnings("unchecked")
	public static Map<String, Object> object(Object value) {
		if (!(value instanceof Map<?, ?>)) {
			throw new IllegalArgumentException("Expected a JSON object");
		}
		return (Map<String, Object>) value;
	}

	public static String string(Map<String, Object> object, String key) {
		Object value = object.get(key);
		if (!(value instanceof String string)) {
			throw new IllegalArgumentException("Missing string field: " + key);
		}
		return string;
	}

	@SuppressWarnings("unchecked")
	public static Map<String, Object> optionalObject(Map<String, Object> object, String key) {
		Object value = object.get(key);
		if (value == null) {
			return new LinkedHashMap<>();
		}
		return object(value);
	}

	public static String stringify(Object value) {
		if (value == null) {
			return "null";
		}
		if (value instanceof String string) {
			return quote(string);
		}
		if (value instanceof Number || value instanceof Boolean) {
			return value.toString();
		}
		if (value instanceof Map<?, ?> map) {
			StringBuilder result = new StringBuilder("{");
			boolean first = true;
			for (Map.Entry<?, ?> entry : map.entrySet()) {
				if (!first) {
					result.append(',');
				}
				first = false;
				result.append(quote(String.valueOf(entry.getKey()))).append(':');
				result.append(stringify(entry.getValue()));
			}
			return result.append('}').toString();
		}
		if (value instanceof Iterable<?> iterable) {
			StringBuilder result = new StringBuilder("[");
			boolean first = true;
			for (Object item : iterable) {
				if (!first) {
					result.append(',');
				}
				first = false;
				result.append(stringify(item));
			}
			return result.append(']').toString();
		}
		throw new IllegalArgumentException("Unsupported JSON value: " + value.getClass());
	}

	private static String quote(String value) {
		StringBuilder result = new StringBuilder("\"");
		for (int i = 0; i < value.length(); i++) {
			char character = value.charAt(i);
			switch (character) {
				case '"' -> result.append("\\\"");
				case '\\' -> result.append("\\\\");
				case '\b' -> result.append("\\b");
				case '\f' -> result.append("\\f");
				case '\n' -> result.append("\\n");
				case '\r' -> result.append("\\r");
				case '\t' -> result.append("\\t");
				default -> {
					if (character < 0x20) {
						result.append(String.format("\\u%04x", (int) character));
					}
					else {
						result.append(character);
					}
				}
			}
		}
		return result.append('"').toString();
	}

	private static final class Parser {
		private final String input;
		private int position;

		Parser(String input) {
			this.input = input;
		}

		boolean atEnd() {
			return position >= input.length();
		}

		void skipWhitespace() {
			while (!atEnd() && Character.isWhitespace(input.charAt(position))) {
				position++;
			}
		}

		Object parseValue() {
			skipWhitespace();
			if (atEnd()) {
				throw error("Expected JSON value");
			}
			return switch (input.charAt(position)) {
				case '{' -> parseObject();
				case '[' -> parseArray();
				case '"' -> parseString();
				case 't' -> parseLiteral("true", Boolean.TRUE);
				case 'f' -> parseLiteral("false", Boolean.FALSE);
				case 'n' -> parseLiteral("null", null);
				default -> parseNumber();
			};
		}

		private Map<String, Object> parseObject() {
			Map<String, Object> result = new LinkedHashMap<>();
			position++;
			skipWhitespace();
			if (consume('}')) {
				return result;
			}
			while (true) {
				skipWhitespace();
				if (atEnd() || input.charAt(position) != '"') {
					throw error("Expected object key");
				}
				String key = parseString();
				skipWhitespace();
				expect(':');
				result.put(key, parseValue());
				skipWhitespace();
				if (consume('}')) {
					return result;
				}
				expect(',');
			}
		}

		private List<Object> parseArray() {
			List<Object> result = new ArrayList<>();
			position++;
			skipWhitespace();
			if (consume(']')) {
				return result;
			}
			while (true) {
				result.add(parseValue());
				skipWhitespace();
				if (consume(']')) {
					return result;
				}
				expect(',');
			}
		}

		private String parseString() {
			expect('"');
			StringBuilder result = new StringBuilder();
			while (!atEnd()) {
				char character = input.charAt(position++);
				if (character == '"') {
					return result.toString();
				}
				if (character != '\\') {
					result.append(character);
					continue;
				}
				if (atEnd()) {
					throw error("Unterminated escape");
				}
				char escaped = input.charAt(position++);
				result.append(switch (escaped) {
					case '"' -> '"';
					case '\\' -> '\\';
					case '/' -> '/';
					case 'b' -> '\b';
					case 'f' -> '\f';
					case 'n' -> '\n';
					case 'r' -> '\r';
					case 't' -> '\t';
					case 'u' -> parseUnicode();
					default -> throw error("Invalid escape");
				});
			}
			throw error("Unterminated string");
		}

		private char parseUnicode() {
			if (position + 4 > input.length()) {
				throw error("Invalid unicode escape");
			}
			String digits = input.substring(position, position + 4);
			position += 4;
			try {
				return (char) Integer.parseInt(digits, 16);
			}
			catch (NumberFormatException e) {
				throw error("Invalid unicode escape");
			}
		}

		private Object parseLiteral(String literal, Object value) {
			if (!input.startsWith(literal, position)) {
				throw error("Invalid literal");
			}
			position += literal.length();
			return value;
		}

		private Number parseNumber() {
			int start = position;
			while (!atEnd() && "-+0123456789.eE".indexOf(input.charAt(position)) >= 0) {
				position++;
			}
			String number = input.substring(start, position);
			try {
				return number.contains(".") || number.contains("e") || number.contains("E")
					? Double.parseDouble(number) : Long.parseLong(number);
			}
			catch (NumberFormatException e) {
				throw error("Invalid number");
			}
		}

		private boolean consume(char expected) {
			if (!atEnd() && input.charAt(position) == expected) {
				position++;
				return true;
			}
			return false;
		}

		private void expect(char expected) {
			if (!consume(expected)) {
				throw error("Expected '" + expected + "'");
			}
		}

		private IllegalArgumentException error(String message) {
			return new IllegalArgumentException(message + " at position " + position);
		}
	}
}
