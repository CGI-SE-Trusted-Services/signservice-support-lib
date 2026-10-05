package se.signatureservice.support.utils;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/*
 *  Utility class for resolving higher assurance levels for AuthnContextClassRefs
 */
public class AuthnContextClassRefUtils {

    static List<String> equalOrHigherLoas(List<String> inputs) {
        return inputs.stream().flatMap(input -> equalOrHigherLoa(input).stream()).distinct().collect(Collectors.toList());
    }

    static List<String> equalOrHigherLoa(String input) {
        // try all defined hierarchies to find expansions, or else return the input value as a singleton list
        return Elegnamnden_LoaLevels.tryParse(input).map(Elegnamnden_LoaLevels::orHigher).orElse(
                Elegnamnden_Eidas_LoaLevels.tryParse(input).map(Elegnamnden_Eidas_LoaLevels::orHigher).orElse(
                        Swedenconnect_NonResident_LoaLevels.tryParse(input).map(Swedenconnect_NonResident_LoaLevels::orHigher)
                                .orElse(List.of(input))
                ));
    }

    /*
     * Enumeration of elegnamnden loa levels
     */
    public enum Elegnamnden_LoaLevels {
        loa1("http://id.elegnamnden.se/loa/1.0/loa1"),
        loa2("http://id.elegnamnden.se/loa/1.0/loa2"),
        loa3("http://id.elegnamnden.se/loa/1.0/loa3"),
        loa4("http://id.elegnamnden.se/loa/1.0/loa4");

        private final String value;

        Elegnamnden_LoaLevels(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        List<String> orHigher() {
            return Arrays.stream(Elegnamnden_LoaLevels.values())
                    .filter(l -> l.ordinal() >= this.ordinal())
                    .map(Elegnamnden_LoaLevels::getValue)
                    .collect(Collectors.toList());
        }

        public static Optional<Elegnamnden_LoaLevels> tryParse(String input) {
            for (Elegnamnden_LoaLevels loa : Elegnamnden_LoaLevels.values()) {
                if (loa.value.equals(input)) {
                    return Optional.of(loa);
                }
            }
            return Optional.empty();
        }
    }

    /*
     * Enumeration of elegnamnden eidas loa levels
     */
    public enum Elegnamnden_Eidas_LoaLevels {
        low("http://id.elegnamnden.se/loa/1.0/eidas-low"),
        sub("http://id.elegnamnden.se/loa/1.0/eidas-sub"),
        high("http://id.elegnamnden.se/loa/1.0/eidas-high");

        private final String value;

        Elegnamnden_Eidas_LoaLevels(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        List<String> orHigher() {
            return Arrays.stream(Elegnamnden_Eidas_LoaLevels.values())
                    .filter(l -> l.ordinal() >= this.ordinal())
                    .map(Elegnamnden_Eidas_LoaLevels::getValue)
                    .collect(Collectors.toList());
        }

        public static Optional<Elegnamnden_Eidas_LoaLevels> tryParse(String input) {
            for (Elegnamnden_Eidas_LoaLevels loa : Elegnamnden_Eidas_LoaLevels.values()) {
                if (loa.value.equals(input)) {
                    return Optional.of(loa);
                }
            }
            return Optional.empty();
        }
    }

    /*
     * Enumeration of swedenconnect nonresident loa levels
     */
    public enum Swedenconnect_NonResident_LoaLevels {
        loa2("http://id.swedenconnect.se/loa/1.0/loa2-nonresident"),
        loa3("http://id.swedenconnect.se/loa/1.0/loa3-nonresident"),
        loa4("http://id.swedenconnect.se/loa/1.0/loa4-nonresident");

        private final String value;

        Swedenconnect_NonResident_LoaLevels(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        List<String> orHigher() {
            return Arrays.stream(Swedenconnect_NonResident_LoaLevels.values())
                    .filter(l -> l.ordinal() >= this.ordinal())
                    .map(Swedenconnect_NonResident_LoaLevels::getValue)
                    .collect(Collectors.toList());
        }

        public static Optional<Swedenconnect_NonResident_LoaLevels> tryParse(String input) {
            for (Swedenconnect_NonResident_LoaLevels loa : Swedenconnect_NonResident_LoaLevels.values()) {
                if (loa.value.equals(input)) {
                    return Optional.of(loa);
                }
            }
            return Optional.empty();
        }
    }


}