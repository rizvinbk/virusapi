<?php
/**
 * Implementation of the public VirusTotal API.
 *
 * @author Andreas Breitschopp (http://www.ab-weblog.com)
 * @copyright Andreas Breitschopp (http://www.ab-weblog.com)
 * @version 1.0
 */
class VirusTotalAPI {
	const URL_API_BASIS = 'https://www.virustotal.com/api/';
	const URL_FILE_REPORT = 'get_file_report.json';
	const URL_SCAN_FILE = 'scan_file.json';
	const URL_URL_REPORT = 'get_url_report.json';
	const URL_SCAN_URL = 'scan_url.json';
	const URL_MAKE_COMMENT = 'make_comment.json';

	private $_key;

	public function __construct($key) {
		$this->_key = $key;
	}
	
	/**
	 * Retrieve a file scan report.
	 *
	 * @param string $resource A md5/sha1/sha256 hash (e. g. a scan ID) will retrieve the most recent report on a given sample. You may also specify a permalink identifier (sha256-timestamp as returned by the file upload API) to access a specific report.
	 * @return object An object containing the scan report or a result code:
	 * -2: public API request rate exceeded.
	 * -1: wrong API key.
	 *  0: no results for searched item.
	 */
	public function getFileReport($resource) {
		$parameters = array(
				'resource' => $resource
			);

		return $this->_doCall(VirusTotalAPI::URL_FILE_REPORT, $parameters);
	}
	public function getFileReport1($resource) {
		$parameters = array(
				'resource' => $resource
			);

		return $this->_doCall1(VirusTotalAPI::URL_FILE_REPORT, $parameters);
	}
	/**
	 * Send and scan a file.
	 *
	 * @param string $filePath A relative path to the file.
	 * @return object An object containing the scan ID for getting the report later on or a result code:
	 * -3: file not found.
	 * -2: public API request rate exceeded.
	 * -1: wrong API key.
	 */
	public function scanFile($filePath) {
		if (!file_exists($filePath)) {
			return array(
					'result' => -3
				);
		}
		
		$realPath = realpath($filePath);

		if (version_compare(PHP_VERSION, '5.3.0') >= 0) {
			$pathInfo = pathinfo($realPath);
			$fileName = $pathInfo['basename'];
		
			$parameters = array(
					'file' => '@' . $realPath . ';' .
					'type=' . mime_content_type($fileName) . ';' .
					'filename=' . $fileName
				);
		} else {
			// Due to a bug in some older curl versions
			// we only send the file without mime type or file name.
			$parameters = array(
					'file' => '@' . $realPath
				);
		}
		
		return $this->_doCall(VirusTotalAPI::URL_SCAN_FILE, $parameters);
	}
	
	/**
	 * Retrieve a URL scan report.
	 *
	 * @param string $resource A URL will retrieve the most recent report on the given URL. You may also specify a permalink identifier (md5-timestamp as returned by the URL submission API) to access a specific report.
	 * @param bool[optional] $scan Parameter that when set to true will automatically submit the URL for analysis if no report is found for it in VirusTotal's database.
	 * @return object An object containing the scan report or the scan ID (in case a new scan was necessary) or a result code:
	 * -2: public API request rate exceeded.
	 * -1: wrong API key.
	 *  0: no results for searched item.
	 */
	public function getURLReport($resource, $scan = FALSE) {
		$parameters = array(
				'resource' => $resource,
				'scan' => (int)$scan
			);

		return $this->_doCall(VirusTotalAPI::URL_URL_REPORT, $parameters);
	}
	
	/**
	 * Submit and scan an URL.
	 *
	 * @param string $URL The URL that should be scanned.
	 * @return object An object containing the scan ID for getting the report later on or a result code:
	 * -2: public API request rate exceeded.
	 * -1: wrong API key.
	 */
	public function scanURL($URL) {
		$parameters = array(
				'url' => $URL
			);

		return $this->_doCall(VirusTotalAPI::URL_SCAN_URL, $parameters);
	}
	
	/**
	 * Make comments on files.
	 *
	 * @param string $resource A md5/sha1/sha256 hash of the file you want to review.
	 * @param string $comment The actual review, you can tag it using the "#" twitter-like syntax (e.g. #disinfection #zbot) and reference users using the "@" syntax (e.g. @EmilianoMartinez).
	 * @param string[optional] $tags A semi-colon separated list of standard file tags: goodware, malware, spamattachmentorlink, p2pdownload, impropagating, networkworm, drivebydownload.
	 * @return object An object containing a result code:
	 * -2: public API request rate exceeded.
	 * -1: wrong API key.
	 *  1: comment successfully posted.
	 */
	public function makeCommentOnFile($resource, $comment, $tags) {
		return $this->_makeComment('file', $resource, $comment, $tags);
	}
	
	/**
	 * Make comments on URLs.
	 *
	 * @param string $resource The URL that you want to comment on.
	 * @param string $comment The actual review, you can tag it using the "#" twitter-like syntax (e.g. #disinfection #zbot) and reference users using the "@" syntax (e.g. @EmilianoMartinez).
	 * @param string[optional] $tags A semi-colon separated list of standard URL tags: malicious, benign, malwaredownload, phishingsite, browserexploit, spamlink.
	 * @return object An object containing a result code:
	 * -2: public API request rate exceeded.
	 * -1: wrong API key.
	 *  1: comment successfully posted.
	 */
	public function makeCommentOnURL($resource, $comment, $tags) {
		return $this->_makeComment('url', $resource, $comment, $tags);
	}
	
	/**
	 * Get the scan ID of a submission result.
	 *
	 * @param object $result The submission result containing the scan ID.
	 * @return string The scan ID or a result code:
	 * -1: not a valid scan result.
	 */
	public function getScanID($result) {
		if (!isset($result->result)) return -1;
		if ($result->result != 1) return -1;
		if (!isset($result->scan_id)) return -1;
		
		return $result->scan_id;
	}
		
	/**
	 * Display a scan or submission result.
	 *
	 * @param object $result The result that should be displayed.
	 * @return int A result code:
	 * -1: not a valid result.
	 *  1: result successfully displayed.
	 */
	public function displayResult($result) {
		if (!isset($result->result)) return -1;
		if ($result->result != 1) return -1;

		print('<pre>');
		print_r($result);
                
		print('</pre>');
		
		return 1;
	}
	
	/**
	 * Get the submission date of a scan report.
	 *
	 * @param object $report The report thats submission date should be returned.
	 * @return string The submission date of the report or a result code:
	 * -1: not a valid scan report.
	 * 	 */
	public function getSubmissionDate($report) {
		if (!isset($report->result)) return -1;
		if ($report->result != 1) return -1;
		if (!isset($report->report)) return -1;
		
		return $report->report[0];
	}
	
	/**
	 * Get the total number of anti-virus checks performed.
	 *
	 * @param object $report The report thats total number of anti-virus checks should be returned.
	 * @return int The total number of anti-virus checks of the report or a result code:
	 * -1: not a valid scan report.
	 */
	public function getTotalNumberOfChecks($report) {
		if (!isset($report->result)) return -1;
		if ($report->result != 1) return -1;
		if (!isset($report->report)) return -1;
		
		return count((array)$report->report[1]);
	}
	
	/**
	 * Get the number of anti-virus hits.
	 *
	 * @param object $report The report thats number of anti-virus hits should be returned.
	 * @return int The number of anti-virus hits of the report or a result code:
	 * -1: not a valid scan report.
	 */
	public function getNumberHits($report) {
		if (!isset($report->result)) return -1;
		if ($report->result != 1) return -1;
		if (!isset($report->report)) return -1;
		
		$hits = 0;
		foreach ($report->report[1] as $program => $result)
			if ($result != '' &&
				$result != 'Clean site' &&
				$result != 'Unrated site')
				$hits++;

		return $hits;
	}
	
	/**
	 * Get the permalink of the report.
	 *
	 * @param object $report The report thats permalink should be returned.
	 * @param bool[optional] $withDate If true (default) permalink returns exactly the current scan report, otherwise it returns always the most recent scan report.
	 * @return string The permalink of the report or a result code:
	 * -1: not a valid scan report.
	 */
	public function getReportPermalink($report, $withDate = TRUE) {
		if (!isset($report->result)) return -1;
		if ($report->result != 1) return -1;
		if (!isset($report->report)) return -1;
		
		$permalink = $report->permalink;
		if ($withDate)
			return $permalink;
		else
			return substr($permalink, 0, strrpos($permalink, '-'));
	}
	
	/**
	* Getter for the key.
	*
	* @return string The key.
	*/
	public function getKey() {
	    return $this->_key;
	}
	
	/**
	* Setter for the key.
	*
	* @param string $key The new key.
	*/
	public function setKey($key) {
	    $this->_key = $key;
	}
	
	private function _makeComment($type, $resource, $comment, $tags) {
		$parameters = array(
				$type => $resource,
				'comment' => $comment,
				'tags' => $tags
			);

		return $this->_doCall(VirusTotalAPI::URL_MAKE_COMMENT, $parameters);
	}
	
	private function _doCall($apiTarget, $parameters) {
		$postFields = array(
				'key' => $this->_key
			);
		$postFields = array_merge($parameters, $postFields);

		$ch = curl_init(VirusTotalAPI::URL_API_BASIS . $apiTarget);
		curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
		curl_setopt($ch, CURLOPT_FORBID_REUSE, 1);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_VERBOSE, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
		$response = curl_exec($ch);
		curl_close($ch);

		return json_decode($response);
	}
        private function _doCall1($apiTarget, $parameters) {
		$postFields = array(
				'key' => $this->_key
			);
		$postFields = array_merge($parameters, $postFields);

		$ch = curl_init(VirusTotalAPI::URL_API_BASIS . $apiTarget);
		curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
		curl_setopt($ch, CURLOPT_FORBID_REUSE, 1);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_VERBOSE, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
		$response = curl_exec($ch);
		curl_close($ch);

		return json_decode($response,true);
	}
}
?>