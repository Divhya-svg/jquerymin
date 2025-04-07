/**
 * @name jQuery Incomplete Sanitization Detection
 * @description Detects potentially unsafe jQuery operations with incomplete sanitization
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id js/jquery-sanitization
 * @tags security
 *       external/cwe/cwe-79
 *       external/cwe/cwe-116
 */

import javascript
import DataFlow::PathGraph

/**
 * A configuration to detect incomplete sanitization in jQuery operations
 */
class JQuerySanitizationConfig extends DataFlow::Configuration {
  JQuerySanitizationConfig() { this = "JQuerySanitizationConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Sources of untrusted data
    exists(DataFlow::CallNode call |
      // Ajax responses
      call.getMethodName().regexpMatch("(ajax|get|post|load)") and
      source = call.getAMethodCall("done").getArgument(0).getALocalSource()
    )
    or
    // Form inputs, URL parameters
    exists(DataFlow::PropRead read |
      read.getPropertyName().regexpMatch("(value|innerHTML|innerText|textContent)") and
      source = read
    )
    or
    // URL or query parameters
    exists(DataFlow::PropRead read |
      read.getBase().toString().regexpMatch("(location|URL|search|hash)") and
      source = read
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // jQuery methods that can lead to XSS if not sanitized
    exists(DataFlow::MethodCallNode call |
      call.getMethodName().regexpMatch("(html|append|prepend|after|before|replaceWith)") and
      sink = call.getArgument(0)
    )
    or
    // jQuery attribute methods
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "attr" and
      call.getArgument(0).getStringValue().regexpMatch("(href|src|style|on.*)") and
      sink = call.getArgument(1)
    )
    or
    // jQuery evaluation methods
    exists(DataFlow::MethodCallNode call |
      call.getMethodName().regexpMatch("(globalEval|parseHTML)") and
      sink = call.getArgument(0)
    )
  }

  override predicate isBarrier(DataFlow::Node node) {
    // Proper sanitization methods
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(escapeHtml|sanitize|DOMPurify|encodeURI.*)") and
      node = call
    )
    or
    // jQuery's text() method is safe because it escapes HTML
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "text" and
      node = call
    )
    or
    // Check for regex replacement of ALL dangerous characters
    exists(DataFlow::MethodCallNode replace |
      replace.getMethodName() = "replace" and
      replace.getArgument(0).toString().regexpMatch(".*((<|>|\"|'|&).*){4,}.*g") and
      node = replace
    )
  }

  override predicate isBarrierGuard(DataFlow::Node node) {
    // Recognizing type-checking functions as sanitization barriers
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(isString|isURL|isValidInput)") and
      node = call
    )
  }
}

from JQuerySanitizationConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potentially unsafe data from $@ is used in jQuery operation without complete sanitization.", source.getNode(), "user input"
