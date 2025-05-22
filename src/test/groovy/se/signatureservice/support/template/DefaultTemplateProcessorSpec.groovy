/************************************************************************
 *                                                                       *
 *  Signature Service - Support Service Library                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
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
