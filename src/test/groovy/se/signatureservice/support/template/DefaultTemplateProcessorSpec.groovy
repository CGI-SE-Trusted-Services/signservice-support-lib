package se.signatureservice.support.template

import spock.lang.Specification

class DefaultTemplateProcessorSpec extends Specification {
    void "test populateTemplate"(){
        setup:
        TemplateProcessor processor = new DefaultTemplateProcessor()

        when:
        String text = processor.populateTemplate(template, values)

        then:
        text == expectedText

        where:
        template                   | values                          | expectedText
        "Hello {name}"             | [name: "Johnny"]                | "Hello Johnny"
        "{a} is {b} or {c}"        | [a: "cat", b: "dog", c:"mouse"] | "cat is dog or mouse"
        "{unknown} variable"       | [a: "cat", b: "dog", c:"mouse"] | "{unknown} variable"
        "{CaseSens}{casesens}"     | [CaseSens: "dog"]               | "dog{casesens}"
        ""                         | null                            | ""
        ""                         | [:]                             | ""
        null                       | null                            | null
        null                       | [:]                             | null

    }
}
